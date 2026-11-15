#!/usr/bin/env python3
import hashlib, time, unittest
from hub_authority import *

U1="11111111-2222-4333-8444-555555555555"
U2="22222222-3333-4444-8555-666666666666"

class HubAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.s=new_state()
        t=now()
        self.s["users"]["alice"]={"uuid":U1,"created_at":t,"expires_at":0,"quota_bytes":1000,"enabled":True,"access_state":"active","last_activity":0,"online_until":0}
        for n in NODES:self.s["usage_nodes"].setdefault(n,{})["alice"]={"accum":0,"last_raw":0}

    def report(self,node,raw):
        return ingest_usage(self.s,node,{"users":[{"name":"alice","uuid_hash":hashlib.sha256(U1.encode()).hexdigest(),"raw_bytes":raw}]})

    def test_two_node_usage_aggregation_and_reset(self):
        self.report("arvan",100); self.report("parspack",200)
        self.assertEqual(total_usage(self.s,"alice"),300)
        self.report("arvan",180); self.report("parspack",250)
        self.assertEqual(total_usage(self.s,"alice"),430)
        apply_command(self.s,"reset_usage",{"name":"alice"})
        self.assertEqual(total_usage(self.s,"alice"),0)
        self.report("arvan",180); self.report("parspack",250)
        self.assertEqual(total_usage(self.s,"alice"),0)
        self.report("arvan",200); self.report("parspack",300)
        self.assertEqual(total_usage(self.s,"alice"),70)

    def test_quota_enforcement_manifest(self):
        self.report("arvan",700); self.report("parspack",300)
        m=manifest(self.s)
        u=m["users"][0]
        self.assertEqual(u["access_state"],"quota")
        self.assertEqual(u["used_bytes"],1000)

    def test_disable_enable(self):
        apply_command(self.s,"disable",{"name":"alice"})
        self.assertEqual(manifest(self.s)["users"][0]["access_state"],"manual")
        apply_command(self.s,"enable",{"name":"alice"})
        self.assertEqual(manifest(self.s)["users"][0]["access_state"],"active")

    def test_route_links_are_unchanged(self):
        links,_=route_links("alice",U1)
        self.assertIn(PUBLIC_HOSTS["arvan"],links["arvan"])
        self.assertIn(PUBLIC_HOSTS["parspack"],links["parspack"])
        self.assertIn("/tunnel",urllib.parse.unquote(links["arvan"]))
        self.assertIn("/tunnel",urllib.parse.unquote(links["parspack"]))

    def test_dashboard_command_contract(self):
        q=CompatQueue(self.s)
        r=q.enqueue("config",{"name":"alice"})
        self.assertTrue(r["success"])
        self.assertEqual(r["status"],"pending")
        c=q.get_command(r["command_id"])["command"]
        self.assertEqual(c["status"],"done")
        self.assertIn("bundle",c["result"])

    def test_add_delete(self):
        q=CompatQueue(self.s)
        r=q.enqueue("add",{"name":"bob","duration_days":30,"quota_bytes":5000})
        c=q.get_command(r["command_id"])["command"]
        self.assertEqual(c["status"],"done")
        self.assertIn("bob",self.s["users"])
        r=q.enqueue("delete",{"name":"bob"})
        self.assertEqual(q.get_command(r["command_id"])["command"]["status"],"done")
        self.assertNotIn("bob",self.s["users"])

    def test_expiry(self):
        self.s["users"]["alice"]["expires_at"]=now()-1
        self.assertEqual(manifest(self.s)["users"][0]["access_state"],"expired")

if __name__=="__main__":
    unittest.main(verbosity=2)