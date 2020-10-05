import sys, hashlib


PREFIX = b"super-DUPER impossible 2 guess preFIX 1728579"

n = int( sys.argv[1] )  if len(sys.argv) > 1  else   1000

for i in range(n):
   hash = hashlib.sha256(PREFIX + str(i).encode("ascii")).hexdigest()
   print(i, hash[:32])
