# my-nodes

Self-updating free proxy-node subscriptions. A scheduled GitHub Actions
workflow runs every 6 hours:

1. Fetch node lists from multiple public free sources (`sources.yaml`)
2. TCP-test each node for connectivity
3. Regenerate `output/clash.yaml` (ClashMi / Clash Meta) and
   `output/shadowrocket.txt` (Shadowrocket, base64 subscription)
4. Commit back to this repo

## Subscription URLs (jsdelivr, stable)

- ClashMi: `https://cdn.jsdelivr.net/gh/owenlee3/my-nodes@main/output/clash.yaml`
- Shadowrocket: `https://cdn.jsdelivr.net/gh/owenlee3/my-nodes@main/output/shadowrocket.txt`

Add the URL as a subscription in your client and hit "update subscription"
for fresh nodes. The `clash.yaml` includes a `url-test` group so the
client auto-selects working nodes locally.

## Notes

- Free nodes are inherently unstable and can see your traffic — casual
  browsing only, never banking / email / sensitive logins.
- Dependencies: python3 + pyyaml (installed by the workflow).
