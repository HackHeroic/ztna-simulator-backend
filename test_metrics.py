import time
import subprocess

def run_test(cmd):
    start = time.time()
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return (time.time() - start) * 1000, out.stdout

latencies = [run_test('python ztna_client.py login alice@company.com:password123 && python ztna_client.py request-vpn && python ztna_client.py connect-vpn') for _ in range(5)]
avg_latency = sum(l[0] for l in latencies) / 5
print(f"Avg Connect Latency: {avg_latency:.0f}ms")
# Run iperf3 separately for throughput