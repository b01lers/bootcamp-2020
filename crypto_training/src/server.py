import os
import binascii, hashlib, random
import datetime
from flask import Flask, request, render_template
from multiprocessing import Value


import Problem, World
from State import State


###
# create a few things and shortcuts up front
###

world = World.World()

areaExitStrings = [
       ", ".join( [ ex  for (ex, avail) in areaExits.items()  if avail ] )  for  areaExits in world.exits ]


# generate flags

SECRET = b"Let's hope this is reasonably secure 1na9igy3hx0v"
#minicodes = bytes(random.sample(b"ABCDEFGHIJKL", 12) )
minicodes = "KIBDFGCLHAJE"
for i in [3, 5, 9, 13]:
   minicodes = minicodes[:i] + "Q" + minicodes[i:]
print("MINICODES=", minicodes)

flags = []
for i in range(world.roomCount()):
   flags.append([])
   for j in range(Problem.challenges[i].maxLevel + 1):
      hash = hashlib.sha256(SECRET + b":" + str(i).encode() + b":" + str(j).encode()).hexdigest()
      flags[i].append("mini{" + minicodes[i] + str(j + 1) + "_" +  hash[:24] + "}")       
      if minicodes[i] == "A" and j == 0: flags[i][-1] = "mini{A1_27f3abda81e75486b9299fda}"
      if minicodes[i] == "A" and j == 1: flags[i][-1] = "mini{A2_6bb458859e4518dc1e131618}"

for i in range(len(flags[3])):  # starter room flags -> FAKE
   flags[3][i] = "FAKE{" + flags[3][i][8:]

#for i in [5, 9]:   # wizard tower and lab flags -> REAL
#   flags[i][0] = "flag{" + flags[i][0][8:] 
flags[5][0] = "flag{pref1xing_w0uld've_been_b3tter_in_thi5_c4se}"
flags[9][0] = "flag{th1ngs_go_s0uth_wh3n_you_trus7_u5er_input}"


with open("flags.txt", "w") as f:
   for i in flags:
      for j in i:
         f.write(j + "\n")




# flask stuff
#

templateDir = os.path.abspath("./tmpl")
app = Flask(__name__, template_folder = templateDir)
#app.config['SECRET_KEY'] = SECRET


# load tokens - last word on each line
tokenList = []
with open("tokens.txt", "r") as f:
   for l in f:
      tokenList.append( l.strip().split(" ")[-1] )   

#print(tokenList)

# store per-token timestamps in multiprocessing Values for atomic access
ratelimitTimestamps = {}
for t in tokenList:
   ratelimitTimestamps[t] = Value('d', 0.)   # set these waaay in past

ratelimitDeltaT = 20.  # in seconds


# ROUTES
#


# chall10 lvl 3 file (XOR problem)
#
with open("chal10_3.base64", "rb") as f:
   chal10_data = f.read()

@app.route("/chal10", methods = ["GET"])
def chal10_file():
   return chal10_data, 200, {'Content-Type': 'text/plain'}; 


# hidden chall2, sha256 file
#

@app.route("/sha256_recipe", methods = ["GET"])
def hiddenChal2_file():
   src = """
   SECRET = "..........ILLEGIBLE................."
   assert len(SECRET) == 36

   def hashState(state_str):
      padded = state_str + "p"*(64 - len(state_str)) 
      pool = padded + SECRET
      pi  = "3141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117067"
      msg = ""
      for i in range(0, 100, 2):
         idx = int(pi[i:(i+2)])
         msg += pool[i] + pool[idx] + pool[i + 1]
      return hashlib.sha256(msg.encode("ascii")).hexdigest()

   def verifyHash(state_str, hash):
      return hash == hashState(state_str)

   """
   return src, 200, {'Content-Type': 'text/plain'}; 



# login page 
#

def verifyToken(token):
   print(token, tokenList, token in tokenList)
   if token in tokenList: return True
   return False


@app.route("/", methods = ["GET"])
def root():

   if "token" not in request.args:
      return render_template("home.html")

   token = request.args["token"]
   if not verifyToken(token): 
      return authError()

   # verified
   return render_template("client.html", token = token)


def authError():
   return "Unauthorized"


# command api
# 

def badMove(info):
   info["reply"] = "Cannot move there"
   return makeResponse(info)

def badState():
   return authError()

def badLocation():
   return badState()

def badCommand(info):
   info["reply"] = "I did not get that"
   return makeResponse(info)

def badFormat(info):
   info["reply"] = "Bad format (use: answer value1 value2 ...)"
   return makeResponse(info)

def ratelimitAnswer(info, dt):
   info["reply"] = "... silence is golden (" + str(int((ratelimitDeltaT - dt) + 0.5)) + ")"
   return makeResponse(info)

def badAnswer(info):
   token = info["token"]
   # rate cap timestamp bookkeeping
   ts = datetime.datetime.now().timestamp()     # current time
   tsValue = ratelimitTimestamps.get(token)     # stored time
   with tsValue.get_lock():
      tsValue.value = ts      # renew timestamp
   info["reply"] = "Incorrect"
   return makeResponse(info)

def flagReply(location, lvl):
   return "CORRECT! Your flag is " + flags[location][lvl]

def getDescription(location):
   return world.describe(location) + "\n"

def getProblemText(location, lvl):
   problem = Problem.challenges[location]
   return problem.getText(lvl) + "\n"


def makeResponse(info):
   oldState = info.get("packed_state")
   newState = info.get("packed_newstate")
   hash = info.get("state_hash")
   print(f"makeResponse: newState={newState}")
   # if state has not changed, return old packed state
   if newState == None:
      newState = oldState
      location = State.unpack(oldState)["loc"]
   # if new state, add exits & description
   else:
     # enforce correct hash on old state
     if not verifyHash(info):
        info["reply"] = "  ** EXPELLED - You failed to properly harness SHA256 magic **"
        return forceTeleport(info, 0)
     # if passed, do rest
     state = State.unpack(newState)
     location = state["loc"]
     lvl = state["levels"][location]
     info["exits"] = areaExitStrings[location]
     info["desc"] = ""
     oldState = info["state"]
     if oldState["loc"] != location or lvl == 0:  info["desc"] = getDescription(location)
     info["desc"] += getProblemText(location, lvl)
   # update hash, if any
   # - in tower, always give hash
   # - in lab, always give redacted  hash
      # in lab, make sure we have valid hash first
   if location == world.lab:
      if info.get("state_hash") == None  or  not verifyHash(info):
        # during the ctf we had the weaker test below that allows bypass with no hash presented :/
        #if not verifyHash(info):
        info["reply"] = "  ** EXPELLED - You failed to properly harness SHA256 magic **"
        return forceTeleport(info, 15)
   elif location == world.tower or (hash != None and location != world.lab):
      hash = State.hashState(SECRET, newState)
   if hash != None:
      info["state_hash"] = hash
   # keep only needed fields, then send
   #
   for field in ["token", "state", "packed_state", "packed_newstate"]:
      if info.get(field) != None:  info.pop(field)
   info["state"] = newState
   print(f"makeResponse: info={info}")
   return info


#
# action handling
#

def verifyHash(info):
   hash = info.get("state_hash")
   return hash == None or State.verifyHash(SECRET, info["packed_state"], hash)


def forceTeleport(info, location = None):
   state = info["state"]
   if location == None or world.isOffMap(location): location = world.start
   state["loc"] = location
   info["packed_newstate"] = State.pack(state)
   # redo hash, if any (so that it passes the old state check later)
   if info.get("state_hash") != None:
      info["state_hash"] = State.hashState(SECRET, info["packed_state"])
   return makeResponse(info)


def doMove(info, moveName):
   state = info["state"]
   location = state["loc"]
   newLocation = world.move(location, moveName[0])
   if newLocation == location:
      info["exits"] = areaExitStrings[newLocation]  # make hackig easier (give exit info on bad move too)
      return badMove(info)
   # block moves to lab
   #if newLocation == world.lab: 
   #   info["state_hash"] = State.hashState(SECRET, State.pack(state))   # tag on hash
   #   info["reply"] = "  ** You have been MARKED by an overwhelming power of SHA256 Magic **\n"
   #   return forceTeleport(info, 15)
   # update state
   newState = state.copy()
   newState["loc"] = newLocation
   info["packed_newstate"] = State.pack(newState)
   info["reply"] = "You went " + moveName + "."
   return makeResponse(info)


def doAnswer(info, ansValues):
   token = info["token"]
   # check rate limit
   ts = datetime.datetime.now().timestamp()     # current time
   tsValue = ratelimitTimestamps.get(token)
   with tsValue.get_lock():
      dt = ts - tsValue.value
   if dt < ratelimitDeltaT: return ratelimitAnswer(info, dt)
   # convert answers to int (format check)
   # + sanity checks to take burden off challenge checkers - FIXME: hardcoded
   try:
      lengthBAD = any([ len(v) >= 500 for v in ansValues ])
      countBAD = len(ansValues) >= 15
      if lengthBAD or countBAD:  return badFormat(info)
      answer = [ int(v)  for v in ansValues ]
   except:
      return badFormat(info)
   # check against correct answer
   state = info["state"]
   location = state["loc"]
    # in lab, make sure we have valid hash first
    if location == world.lab:
      if info.get("state_hash") == None  or  not verifyHash(info):
        # during the ctf we had the weaker test below that allows bypass with no hash presented :/
        #if not verifyHash(info):
        info["reply"] = "  ** EXPELLED - You failed to properly harness SHA256 magic **"
        return forceTeleport(info, 15)
   lvl = state["levels"][location]
   problem = Problem.challenges[location]
   correct = problem.isCorrect(answer, lvl)
   if correct == None:  return badFormat(info)
   if correct == False: return badAnswer(info)
   # if correct
   info["reply"] = flagReply(location, lvl)
   newState = state.copy()
   newState["levels"][location] += 1
   info["packed_newstate"] = State.pack(newState)
   return makeResponse(info)


def doReset(info):
   state = info["state"]
   location = state["loc"]
   newState = state.copy()
   newState["levels"][location] = 0
   print(f"newState={newState}")
   info["packed_newstate"] = State.pack(newState)
   info["reply"] = "Challenge RESET successful."
   return makeResponse(info)


@app.route("/api", methods = ["GET"])
def act():

   info = {}

   # verify token
   if "token" not in request.args:
      return authError()
   token = request.args['token']
   if not verifyToken(token): return authError()

   print(f"/api: token={token}")
   info["token"] = token

   # get state

   if "state" not in request.args:  # if none, use default and move to start
      statePacked = State.default(world.roomCount(), 0)
      state = State.unpack(statePacked)
      info["packed_state"] = statePacked
      info["state"] = state
      return forceTeleport(info)
   else:  statePacked = request.args["state"]

   print(f"statePacked={statePacked}")

   state = State.unpack(statePacked)
   if state == None: return badState()

   print(f"state={state}")

   # location
   location = state["loc"]
   if world.isOffMap(location):  return badLocation()

   levels = state["levels"]
   print(f"loc={location}, levels={levels}")

   info["packed_state"] = statePacked
   info["state"] = state

   # check whether we got a hash
   if "state_hash" in request.args:
      info["state_hash"] = request.args["state_hash"]

   # if no command, treat it like a move to current state
   if "comm" not in request.args:
      info["packed_newstate"] = info["packed_state"]
      return makeResponse(info)

   # parse command

   comm_raw = request.args["comm"]
   comm = [ c  for c in comm_raw.split(" ")  if c != "" ]
   if comm == []: return badCommand(info)

   print(f"comm={comm}")

   # if movement
   moveset = ["east", "e", "west", "w", "north", "n", "south", "s"]
   if comm[0] in moveset:
      if len(comm) > 1:   return badCommand(info)
      moveName = moveset[moveset.index(comm[0]) & 6]  # standardize to long name
      return doMove(info, moveName)

   # if answer
   elif comm[0] in ["answer", "ans"]:
      return doAnswer(info, comm[1:])

   # if reset
   elif comm[0] == "RESET":  return doReset(info)

   # other
   else:   return badCommand(info)



if __name__ == "__main__":
   app.run("0.0.0.0", 5000)
