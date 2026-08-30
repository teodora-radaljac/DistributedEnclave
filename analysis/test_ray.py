import ray
import time
import sys

ray.init(address="auto")

@ray.remote
def double(x):
    return x + x

print("Waiting for CVM worker to appear...")
deadline = time.time() + 120
while True:
    workers = [n for n in ray.nodes() if n["Alive"] and not n.get("IsHeadNode")]
    if workers:
        break
    if time.time() > deadline:
        print("Timed out waiting for worker", file=sys.stderr)
        sys.exit(1)
    time.sleep(2)

print(f"Worker connected: {workers[0]['NodeManagerAddress']}")

for x in [0, 1, 21, -5]:
    result = ray.get(double.remote(x))
    assert result == x + x, f"double({x}) = {result}, want {x + x}"
    print(f"double({x}) = {result}")

print("All tests passed.")
