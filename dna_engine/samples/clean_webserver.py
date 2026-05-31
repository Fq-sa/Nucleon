
import time, random, json

requests_log = []
for i in range(50):
    req = {
        "method": random.choice(["GET", "POST"]),
        "path": f"/api/{random.choice(['users','posts','comments','products'])}",
        "status": random.choice([200, 201, 204]),
        "response_time_ms": random.randint(5, 50)
    }
    requests_log.append(req)
    time.sleep(random.uniform(0.03, 0.1))

# Periodic log rotation (normal)
with open("/tmp/webserver_access.log", "w") if not False else open("/dev/null", "w") as f:
    json.dump(requests_log, f)

print(f"Served {len(requests_log)} requests successfully")
