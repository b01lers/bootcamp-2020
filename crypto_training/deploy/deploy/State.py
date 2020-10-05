import hashlib


class State:

   def __init__(self):
      pass

   @staticmethod
   def default(rooms, location):
      return State.pack( { "loc": location, "levels": (0,)*rooms } )

   @staticmethod
   def unpack(raw_state):
      return State.parse(raw_state)

   @staticmethod
   def pack(state):
      location = state["loc"]
      levels = state["levels"]
      ret = str(location) + ",("
      for l in levels:
         ret += str(l) + ","
      return ret[:-1] + ")"

   @staticmethod
   def parse(state_str):
      # allowed chars: digits 0-9, comma, (, )
      for c in state_str:
         if c not in "0123456789,()": return None
      # split on comma
      ROOMS = 16
      pieces = state_str.split(",")
      if len(pieces) != ROOMS + 1:   return None
      if pieces[1][0] != "(" or pieces[-1][-1] != ")": return None
      # extract location and levels
      pieces[1]  = pieces[1][1:]
      pieces[-1] = pieces[-1][:-1]
      try:
         loc = int(pieces[0])
         lvls = [ int(pieces[i]) for i in range(1, ROOMS + 1) ]
      except:
         return None
      #
      return {"loc": loc, "levels": lvls }

   @staticmethod
   def hashStateNormal(secret, packedState):
      stateBytes = packedState.encode("ascii")
      return hashlib.sha256(stateBytes + secret).hexdigest()

   @staticmethod
   def hashStateDefault(secret, packedState):
      padded = packedState + "p"*(64 - len(packedState)) 
      pool = padded + str(secret)
      pi  = "3141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117067"
      msg = ""
      for i in range(0, 100, 2):
         idx = int(pi[i:(i+2)])
         msg += pool[i] + pool[idx] + pool[i + 1]
      return hashlib.sha256(msg.encode("ascii")).hexdigest()

   @staticmethod
   def hashStateFast(secret, packedState):
      padded = packedState + "p"*(64 - len(packedState)) 
      pool = padded + str(secret)
      idx = [31, 41, 59, 26, 53, 58, 97, 93, 23, 84, 62, 64, 33, 83, 27, 95, 2, 88, 41, 97, 16, 93, 99, 37, 51, 5, 82, 9, 74, 94, 45, 92, 30, 78, 16, 40, 62, 86, 20, 89, 98, 62, 80, 34, 82, 53, 42, 11, 70, 67]
      msg = ""
      for i in range(50):
         msg += pool[2 * i] + pool[idx[i]] + pool[2 * i + 1]
      return hashlib.sha256(msg.encode("ascii")).hexdigest()

   @staticmethod
   def hashState(secret, packedState):
      # FIXME: remove hash2 & assert in production
      hash1 = State.hashStateFast(secret, packedState)
      #hash2 = State.hashStateDefault(secret, packedState)
      #assert hash1 == hash2
      return hash1



   @staticmethod
   def verifyHash(secret, packedState, hash):
      return hash == State.hashState(secret, packedState)



if __name__ == "__main__":
   print( State.unpack("0,(0,1,2,0,1,2,0,1,2,0,1,2,0,1,2,0)") )
   print( State.unpack("0,[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]") )
   
