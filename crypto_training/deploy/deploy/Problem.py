import hashlib

####
# general class
####

class Problem:

   # init with no problems
   def __init__(self):
      self.descriptions = []
      self.problems = []
      self.checkers = []
      self.argnums  = []    # if argnums == 0, then we will not disclose the number in isCorrect()
      self.maxLevel = -1

   # set all problems
   def setAll(problem_texts, checkers, argnums):
      maxLvl = min(len(problem_texts), len(checkers), len(argnums) )
      self.maxLevel = maxLvl
      self.problems = problem_texts[:maxLvl]
      self.checkers = checkers[:maxLvl]
      self.argnums  = argnums[:maxLvl]

   # append one more problem
   def append(self, problem_text, checker, argnum):
      self.maxLevel += 1
      self.problems.append(problem_text)
      self.checkers.append(checker)
      self.argnums.append(argnum)

   # return problem text for a given lvl - if no such level, give None
   def getText(self, lvl):
      if self.maxLevel < 0:          return ""
      if 0 <= lvl <= self.maxLevel:  return self.problems[lvl]
      if lvl == self.maxLevel + 1:   return "COMPLETED all levels in this area."
      else:  return None

   # answer is a list of numbers, level is the challenge level
   # return true if correct, false if not
   def isCorrect(self, answer, lvl):
      # check format
      if lvl < 0 or lvl > self.maxLevel:    return None
      if self.argnums[lvl] != 0 and len(answer) != self.argnums[lvl]:  return None
      try:
         numericAns = [ int(a)  for a in answer ]
      except:
         return None
      # verify answer
      print(f"answer={answer}, lvl={lvl}")
      return self.checkers[lvl](numericAns)


####
# challenges
####

challenges = []    # <- insert to this in grid order


###
# 0:  welcome room
###
chall0 = Problem()
chall0_checker1 = lambda ans: ans[0] == 1 + 1 
chall0_checker2 = lambda ans: ans[0] == 3 - 5
chall0_checker3 = lambda ans: ans[0] == 1 and ans[1] == 3 and ans[2] == 7

chall0.append("LEVEL 1: Add 1 and 1.",   chall0_checker1, 1)
chall0.append("LEVEL 2: Subtract 5 from 3.",   chall0_checker2, 1)
chall0.append("LEVEL 3: put the numbers 3, 1, 7 into increasing order.", chall0_checker3, 3)

###
# 1: xgcd
###
chall1 = Problem()

# -16, 11
a1_1, b1_1 = 123, 179
# 784426129, -485011369
a1_2, b1_2 = 5419637592, 8765372543
# 
c1_3 = 13657769199596610482
a1_3 = c1_3 * 12617698590143720670105762881622356815112515386462293667169823660898072508624401058886304920052577927970694376976199218570158447390981717458298614991002613921656481585724247919217255094989084155044494751122113059936231590732548449198257256744354283361036611847588757752920903623201677634807208201686341
b1_3 = c1_3 * 2076236718625626284786056548669081403252544833904150272620011321468023352698988020061877478954752520310301256063072706784500193505113362705334165063487549462926151531407283657215977245889022376851044969477993092232992382813863369202004336646022589496537922628139644127129411273468794581736968001955685
# 
x1_3= -716740480992306813107503753418846234036640156759836661475354416766574545237010296962263824224509107612115141091065808866650335667339422168844609337650456083904714828583142795906730708621014510898197333708554115609551003952289103814240209709219851287729419355090392174924377596434397802758684489757519
y1_3= 4355772766846172289550960484253309708628309981859354451608388213582133495086922647575976048691479746491014530235602502674014803098803037825125357480987981590580196394415483266364546368978087653972266116991312510608494888084750532763692967382260459363590590286778039861513365053641201896497684198556508


chall1_checker1 = lambda ans: ans[0] * a1_1 + ans[1] * b1_1 == 1
chall1_checker2 = lambda ans: ans[0] * a1_2 + ans[1] * b1_2 == 1 
chall1_checker3 = lambda ans: (ans[0] * a1_3 + ans[1] * b1_3 == c1_3) and x1_3 == ans[0] and y1_3 == ans[1]

chall1.append("LEVEL 1: find integers x and y that satisfy " + str(a1_1) + "*x + " + str(b1_1) + "*y = 1", chall1_checker1, 2)
chall1.append("LEVEL 2: find integers x and y that satisfy " + str(a1_2) + "*x + " + str(b1_2) + "*y = 1", chall1_checker2, 2)
chall1.append(
       "LEVEL 3: give the integers x and y that satisfy a*x + b*y = c with smallest\n"
       "         possible |x| + |y|:\n\n"
       "  a = " + str(a1_3) + "\n  b = " + str(b1_3) + "\n  c = " + str(c1_3) 
    , chall1_checker3, 2)


###
#2: crt
###

chall2 = Problem()

# 412
r2_1, p2_1 = [2, 6, 9], [5, 7, 13]
# 6429412122
r2_2, p2_2 = [616, 1892, 3267], [1277, 3911, 6833]
# 
r2_3 = [
  2661929484162718513247006741545910067104673680,
  1051667267149052195100488400753935294543177150,
  47216332074545827727316304129354717936,
  532886655965436047074701814450039258213526,
  11163090230050187304714123613300073905576382766
]
p2_3 = [
  5485948154512337139220437723513046430670172804,
  2108813835706513804248871264701897235977426762,
  59351473308659155928757459746804856485,
  924847477382640006890848669912858050701990,
  12741718618862212680555500636008445150492416265
]
ans2_3 = 1202114787574073135698562247558599073285047132156573830145908717087719050384755928081340071169158043961005726049447510357364537073462416777364540618918830057496883942982657669805211370184463326656


chall2_checker1 = lambda ans: all( [ ans[0] % p2_1[i] == r2_1[i]  for i in range(3) ] )
chall2_checker2 = lambda ans: all( [ ans[0] % p2_2[i] == r2_2[i]  for i in range(3) ] )
chall2_checker3 = lambda ans: all( [ ans[0] % p2_3[i] == r2_3[i]  for i in range(3) ] ) and ans[0] == ans2_3

chall2.append(
    "LEVEL 1: find a number that gives a remainder of " + str(r2_1[0]) + " when divided by " + str(p2_1[0]) + ",\n"
    "         a remainder of " + str(r2_1[1]) + " when divided by " + str(p2_1[1]) + ", and a remainder of " + str(r2_1[2]) + " when\n"
    "         divided by " + str(p2_1[2])
    , chall2_checker1, 1)
chall2.append(
    "LEVEL 2: find a number that gives a remainder of " + str(r2_2[0]) + " when divided by " + str(p2_2[0]) + ",\n"
    "         a remainder of " + str(r2_2[1]) + " when divided by " + str(p2_2[1]) + ", and a remainder of " + str(r2_2[2]) + "\n"
    "         when divided by " + str(p2_2[2])
    , chall2_checker2, 1)

chall2.append( 
       "LEVEL 3: give the smallest positive x that satisfies x mod a_i = b_i, where\n\n"
       "  a1 = " + str(p2_3[0]) + "\n"
       "  a2 = " + str(p2_3[1]) + "\n"
       "  a3 = " + str(p2_3[2]) + "\n"
       "  a4 = " + str(p2_3[3]) + "\n"
       "  a5 = " + str(p2_3[4]) + "\n\n"
       "  b1 = " + str(r2_3[0]) + "\n"
       "  b2 = " + str(r2_3[1]) + "\n"
       "  b3 = " + str(r2_3[2]) + "\n"
       "  b4 = " + str(r2_3[3]) + "\n"
       "  b5 = " + str(r2_3[4])
    , chall2_checker3, 1)


###
#3: factoring
###

chall3 = Problem()


def prod(x):
   j = 1
   for i in x:  j *= i
   return j

#
p3_1 = 48263
a3_1 = [17, 17, 167]
#
p3_2 = 8477969543906630921459041527576694
a3_2 = [2, 7, 7, 13, 19, 19, 79, 601, 234490397, 1655726489421517]
# 5 minutes with yafu / QFS
p3_3 = 71142975216676910225445498956472658317166395374468624230332488059276850400024521063814543607909086075571109949
a3_3 = [3, 11, 31, 29515817, 1075612307646757041328543, 1810939816479001125535889581, 
        1209600061687323613153983466766686569317548327433]

assert prod(a3_1) == p3_1
assert prod(a3_2) == p3_2
assert prod(a3_3) == p3_3


chall3_checker1 = lambda ans: len(ans) == len(a3_1)  and  sorted(ans) == a3_1
chall3_checker2 = lambda ans: len(ans) == len(a3_2)  and  sorted(ans) == a3_2
chall3_checker3 = lambda ans: len(ans) == len(a3_3)  and  sorted(ans) == a3_3

chall3.append(
    "LEVEL 1: factor the number " + str(p3_1) + ". (E.g., for 12, you would answer 2 2 3)"
    , chall3_checker1, 0)
chall3.append(
    "LEVEL 2: factor the number " + str(p3_2) + ". (E.g., for 12, you would answer 2 2 3)"
    , chall3_checker2, 0)
chall3.append("LEVEL 3: factor the number " + str(p3_3), chall3_checker3, 0)



###
#4: primality
###

chall4 = Problem()

ans4_1 = 43
ans4_2 = 5852187
ans4_3 = 10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018661

chall4_checker1 = lambda ans: ans[0] == ans4_1
chall4_checker2 = lambda ans: ans[0] == ans4_2
chall4_checker3 = lambda ans: ans[0] == ans4_3

chall4.append("LEVEL 1: how many primes are there between 1200 and 1500?", chall4_checker1, 1)
chall4.append("LEVEL 2: how many primes are there between 123456780 and 234567890?", chall4_checker2, 1)
chall4.append("LEVEL 3: what is the 16th prime number after 10^400?", chall4_checker3, 1)



####
#5: lin system
####

chall5 = Problem()

# 111, 275
A5_1, B5_1, C5_1 =  76, 221,  85
D5_1, E5_1, F5_1 = 171, 190, 138
N5_1 = 281
# 5415645, 1561936
A5_2, B5_2, C5_2 = 8537681, 2471394, 1901941
D5_2, E5_2, F5_2 = 4650550, 6247615, 1098848
N5_2 = 8715383
#
Coeffs5_3 = [[21831285386116329336808413851154012866, 134179293514007351709197019177330444915], [122250463455825590287911447642817402561, 380808038683121265859993106659221016535], [348695986646393565943251192097904044414, 154755784779510244395471253499438548399]]
Mods5_3 = [330381653200657403372617268197336743779, 167613919641031436550368729835629765957, 19514348735351843258338241386050978799]

ans5_3 = [ 43674417398322942030809924714960023918,
           260639507265100552695534763765703079339,
           515698084587081313853676972411220991033 ]


chall5_checker1 = lambda ans: ((A5_1 * ans[0] + B5_1 * ans[1]) % N5_1) == C5_1 and ((D5_1 * ans[0] + E5_1 * ans[1]) % N5_1) == F5_1
chall5_checker2 = lambda ans: ((A5_2 * ans[0] + B5_2 * ans[1]) % N5_2) == C5_2 and ((D5_2 * ans[0] + E5_2 * ans[1]) % N5_2) == F5_2
chall5_checker3 = lambda ans: ans == ans5_3

chall5.append(
      "LEVEL 1: solve the equations below for x and y\n\n"
      "         (" + str(A5_1) + "*x + " + str(B5_1) + "*y) mod " + str(N5_1) + " = " + str(C5_1) + "\n" 
      "         (" + str(D5_1) + "*x + " + str(E5_1) + "*y) mod " + str(N5_1) + " = " + str(F5_1) 
    , chall5_checker1, 2)
chall5.append(
      "LEVEL 2: solve the equations below for x and y\n\n"
      "         (" + str(A5_2) + "*x + " + str(B5_2) + "*y) mod " + str(N5_2) + " = " + str(C5_2) + "\n" 
      "         (" + str(D5_2) + "*x + " + str(E5_2) + "*y) mod " + str(N5_2) + " = " + str(F5_2) 
    , chall5_checker2, 2)
chall5.append(
      "LEVEL 3: find x, y, and N, if we know that N is a prime and \n\n"
      "           (A*x + B*y) mod N = C\n"
      "           (D*x + E*y) mod N = F\n"
      "           (G*x + H*y) mod N = I\n\n"
      "  A = " + str(Coeffs5_3[0][0]) + "\n"
      "  B = " + str(Coeffs5_3[0][1]) + "\n"
      "  C = " + str(Mods5_3[0]) + "\n"
      "  D = " + str(Coeffs5_3[1][0]) + "\n"
      "  E = " + str(Coeffs5_3[1][1]) + "\n"
      "  F = " + str(Mods5_3[1]) + "\n"
      "  G = " + str(Coeffs5_3[2][0]) + "\n"
      "  H = " + str(Coeffs5_3[2][1]) + "\n"
      "  I = " + str(Mods5_3[2])
    , chall5_checker3, 3)



###
#6: discrete log
###

chall6 = Problem()

# 39
a6_1, b6_1 = 11, 27
p6_1 = 101
# 1768477821
a6_2, b6_2 = 29, 2170396238
p6_2 = 2582957213
# 2358697945552082059831024947255593385327909489688503720985669006663859246025385029464531254734282657195481160704251786434990612691815052924908045078
a6_3, b6_3 = 137, 3351664603444796351468067743627025603502901539830658952546789142275777455261591099982137670634903607997743639964603135521965024437504489798875078878193244768
p6_3 = 8711397949111576691212959376786755312511985069545395246877440965077478774468934756001391309042286116978264258298558869771314939991001082398339822258440522123
# ^^ deliberately not prime
ans6_3 = 2358697945552082059831024947255593385327909489688503720985669006663859246025385029464531254734282657195481160704251786434990612691815052924908045078

assert pow(a6_3, ans6_3, p6_3) == b6_3


chall6_checker1 = lambda ans: abs(ans[0]) < 10**10 and pow(a6_1, ans[0], p6_1) == b6_1
chall6_checker2 = lambda ans: abs(ans[0]) < 10**15 and pow(a6_2, ans[0], p6_2) == b6_2
chall6_checker3 = lambda ans: ans[0] == ans6_3

chall6.append(
     "LEVEL 1: find an integer that satisfies " + str(a6_1) + "^x mod " + str(p6_1) + " = " + str(b6_1) + "\n"
     "         (here ^ means exponentiation, e.g., 2^7 mod 5 = 3)"
    , chall6_checker1, 1)
chall6.append(
     "LEVEL 2: find an integer that solves " + str(a6_2) + "^x mod " + str(p6_2) + " = " + str(b6_2)
    , chall6_checker2, 1)
chall6.append(
     "LEVEL 3: give the smallest positive integer that solves " + str(a6_3) + "^x mod a = b, where\n\n"
     "  a = " + str(p6_3) + "\n"
     "  b = " + str(b6_3)
    , chall6_checker3, 1)


###
#7: roots mod p
###

chall7 = Problem()

# 31, 66 (two roots)
a7_1 = 88
p7_1 = 97
# 548653309, 810550192  (two roots)
a7_2 = 95422207
p7_2 = 1359203501
# (six roots but we want the smallest)
a7_3 = 1817525449797280602402956873386237720889680621662448878394577537780771524786955876245638699592180826704996032326091618875207339103593277472500067216389870
p7_3 = 12779849905941677959186610420316494198424452561778642658582451521063175469853171114961122342052464710078864014592127176275630898014968982060325361045608439
n7_3 = 12
ans7_3 = 1432348556679097207976924262798432006319493853972676670846733320373362810364769377239428651127560672320871090332377840183689975753063716953112491414617177

chall7_checker1 = lambda ans: (ans[0]**2) % p7_1 == a7_1
chall7_checker2 = lambda ans: (ans[0]**2) % p7_2 == a7_2
chall7_checker3 = lambda ans: ans[0] == ans7_3

chall7.append("LEVEL 1: find an integer that satisfies x^2 mod " + str(p7_1) + " = " + str(a7_1),
              chall7_checker1, 1)
chall7.append("LEVEL 2: find an integer that satisfies x^2 mod " + str(p7_2) + " = " + str(a7_2),
              chall7_checker2, 1)
chall7.append(
   "LEVEL 3: give the smallest positive x for which x^" + str(n7_3) + " mod p = a, where\n\n"
   "         a = " + str(a7_3) + "\n"
   "         p = " + str(p7_3)
 , chall7_checker3, 1)



###
#8: LLL 
###

chall8 = Problem()

#(-13, 6, 7), (-8, 23, -23)  and -1 times these
c8_1 = [299, 355, 251]
s8_1 = [str(v) for v in c8_1]
max8_1 = 30
# (144168, -59243, -222326), (-128203, 277543, -138757)  and -1 times these
c8_2 = [69925405969, 48507179354, 32417688895]
max8_2 = 10**6
#
c8_3 = [13224482656452729965010130774472519546513322282685222044383028560173414320699907502364037066998078684364749338920872578811245752029508639952579415409556998, 11883954373554361547375474750630839024678353968736077156027924497730635501467831406890604708209797932039373450099216323200104673509462816247739552390501700, 12033890847356726156410304461564041151269011907532227202193795241332802954932830212451456439198182308280974025227196605722871001660179705508977260220793964, 2844873315637923430702813720068362602065731767047450571384220379074997608589211929239202046737041926913187483721774104817975966051912270671035046621837635, 2606527713655043968153387630347865477764170887107821220448557599575906298221841101758877277715742039004267346644911989983884822836245158485633146455362314]
ans8_3 = [46055792207031492585236658546307916091, 135029002737367008698739296443923408615, -211401559242938519900587929871669033253, 143756772417090339210360644246443259238, -30204570393449551872754737407297785954]
ans8_3_neg = [ -v  for v in ans8_3 ]

chall8_checker1 = lambda ans: max( [ abs(v) for v in ans ]) < max8_1 and min( [ abs(v) for v in ans ]) > 0 and sum([ c*v for c,v in zip(c8_1,ans)]) == 0
chall8_checker2 = lambda ans: max( [ abs(v) for v in ans ]) < max8_2 and min( [ abs(v) for v in ans ]) > 0 and sum([ c*v for c,v in zip(c8_2,ans)]) == 0
chall8_checker3 = lambda ans: ans == ans8_3 or ans == ans8_3_neg

chall8.append(
     "LEVEL 1: find *small* nonzero integers x, y, z that satisfy " + str(c8_1[0]) + "*x + " + str(c8_1[1]) + "*y + " + str(c8_1[2]) + "*z = 0\n"
     "         (e.g., x = " + s8_1[1] + "*" + s8_1[2] + ", y = " + s8_1[0] + "*" + s8_1[2] + ", z = -2*" + s8_1[0] + "*" + s8_1[1] + " does not count)"
    , chall8_checker1, 3)
chall8.append(
     "LEVEL 2: find small nonzero integers x, y, z that satisfy a*x + b*y + c*z = 0,\n"
     "         where a=" + str(c8_2[0]) + ", b=" + str(c8_2[1]) + ", c=" + str(c8_2[2])
    , chall8_checker2, 3)
chall8.append(
     "LEVEL 3: find nonzero integers v, w, x, y, z with a minimal sum of squares\n"
     "         that satisfy a*v + b*w + c*x + d*y + e*z = 0, where\n\n"
     "  a= " + str(c8_3[0]) + "\n"
     "  b= " + str(c8_3[1]) + "\n"
     "  c= " + str(c8_3[2]) + "\n"
     "  d= " + str(c8_3[3]) + "\n"
     "  e= " + str(c8_3[4])
    , chall8_checker3, 5)


####
# 9: hash POW -> wizard tower
####

chall9 = Problem()

# 2468097531
hash9 = "fa0111"

chall9_checker = lambda ans: hashlib.sha256(str(ans[0]).encode("ascii")).hexdigest()[:6] == hash9

chall9.append(
     "FIND: an integer that, written in ASCII decimal, hashes to " + hash9 + "...\n"
     "      (e.g., the number 1 hashes to 6b86b2...875b4b)"
    , chall9_checker, 1)


####
# 10: XOR
####

chall10 = Problem()

# key: 0x69
ctxt10_1 = "PQEMSRoMChsMHUkABx0MDgwbSQAaSR0eDAcdEEQPAB8MSR0BBhwaCAcNRUkPAB8MSQEcBw0bDA1JCAcNSR0eDAUfDEc="
# key: 0x4a9f286e
ctxt10_2 = (
   "BfEIGiL6CAE+900cavdJAC6zCBkvv0wLJPBdACn6CBkj60BOOPZPBj76Rxs5v0EALvZPACvrQQEk\n"
   "v0kALr9MBznzQQUvv0ULJL9fBiW/SRwvv1sBav1NCT/2RAsuv0kALr9MCyfwWg8m9lILLr9KF2rr\n"
   "QAtq/EAPOPJbTiX5CB4m+kkdP+1NTiX5CBoi+ggDJfJNAD6zCB0lv0oCI/FMCy6/Shdq+00dI+1N\n"
   "QmrrQA8+v1wGL+YIDSvxRgE+v04BOPpbCy+/XAYvv1gPI/EIDyT7CBo48F0MJvoIGiL+XE4r7U1O\n"
   "KPBdAC6/XAFq+kYdP/oTTivxTE4v7ghOHvdNTiPxXAst+lpOM/BdTj3+Rhpq9ltOe6wIGiW/XAYv\n"
   "vxlfPvcIHiXoTRxk" )
# LVL3 key: 0xed98c444ea8acd9977031d048822059610297ff9e883c83d99afe04910a093
# this is in chal10_3.txt served over HTTP by the server


ans10_1 = 25512
ans10_2 = 13**11  #1792160394037 
#419797111204456911416422273621730563266064217188764214578604591487313289363
ans10_3 = 0xed98c444ea8acd9977031d048822059610297ff9e883c83d99afe04910a093

chall10_checker1 = lambda ans: ans[0] == ans10_1
chall10_checker2 = lambda ans: ans[0] == ans10_2
chall10_checker3 = lambda ans: ans[0] == ans10_3

chall10.append(
     "LEVEL 1: the base64-encoded string below corresponds to XOR-encrypted\n"
     "         text, with key length of 1 byte. What is the integer in the\n"
     "         message?\n\n" + ctxt10_1
    , chall10_checker1, 1)
chall10.append(
     "LEVEL 2: the base64-encoded string below corresponds to XOR-encrypted\n"
     "         text, with key length of 4 bytes. What is the integer in the\n"
     "         message?\n\n" + ctxt10_2
    
    , chall10_checker2, 1)
chall10.append(
     "LEVEL 3: the base64-encoded file served at http://[THIS_HOST]/chal10\n"
     "         corresponds to XOR-encrypted text, with unknown key length.\n"
     "         What is the *key*, represented as a little-endian integer?"
    , chall10_checker3, 1)



####
# 11: MITM
####

chall11 = Problem()

# 185,232
ctxt11_1   = "0e88440701074a7a0ce6a8cb9d93a5bb"
ptxt11_2_1 = "23df1b9f02d5d50702bfc77f0328dd94"
ctxt11_2_1 = "4311bffa7d121a5f1586faf15afc4605"
ans11_1 = 2736495870102169
# 44230, 29315
ctxt11_2   = "0294c9250b515e1686ba600a0b23d767"
ptxt11_2_2 = "23df1b9f02d5d50702bfc77f0328dd94"
ctxt11_2_2 = "a6a28395f882097d1f542db61ee2a4bd"
ans11_2 = 8143643096686783
# 7312010, 11692107
ctxt11_3   = "42c10856b60a631c4fb4b936ef9546ff"
ptxt11_2_3 = "23df1b9f02d5d50702bfc77f0328dd94" 
ctxt11_2_3 = "842c99112b424fb7096d4347f4901daf"
ans11_3 = 6523399189690767

chall11_checker1 = lambda ans: ans[0] == ans11_1
chall11_checker2 = lambda ans: ans[0] == ans11_2
chall11_checker3 = lambda ans: ans[0] == ans11_3

chall11.append(
     "LEVEL 1: a text was encrypted twice with AES-128 in ECB mode, using two\n"
     "         different keys. For both encryptions, the first 15 key bytes were\n"
     "         zero. Recover the 16-digit integer in the message from the\n"
     "         ciphertext. It might help that we also obtained a plaintext,\n"
     "         ciphertext pair from this scheme, with the same keys that were\n"
     "         used for the earlier encryption.\n\n"
     "  ctxt = " + ctxt11_1 + "\n"
     "  ptxt2, ctxt2 = " + ptxt11_2_1 + ", " + ctxt11_2_1
    , chall11_checker1, 1)
chall11.append(
     "LEVEL 2: a text was encrypted twice with AES-128 in ECB mode, using two\n"
     "         different keys. For both encryptions, the first 14 key bytes were\n"
     "         zero. Recover the 16-digit integer in the message from the\n"
     "         ciphertext. It might help that we also obtained a plaintext,\n"
     "         ciphertext pair from this scheme, with the same keys that were\n"
     "         used for the earlier encryption.\n\n"
     "  ctxt = " + ctxt11_2 + "\n"
     "  ptxt2, ctxt2 = " + ptxt11_2_2 + ", " + ctxt11_2_2
    , chall11_checker2, 1)
chall11.append(
     "LEVEL 3: a text was encrypted twice with AES-128 in ECB mode, using two\n"
     "         different keys. For both encryptions, the first 13 key bytes were\n"
     "         zero. Recover the 16-digit integer in the message from the\n"
     "         ciphertext. It might help that we also obtained a plaintext,\n"
     "         ciphertext pair from this scheme, with the same keys that were\n"
     "         used for the earlier encryption. (By the way, those who really\n"
     "         know what they are doing would be able to get this with only\n"
     "         12 zeroes...)\n\n"
     "  ctxt = " + ctxt11_3 + "\n"
     "  ptxt2, ctxt2 = " + ptxt11_2_3 + ", " + ctxt11_2_3
    , chall11_checker3, 1)


####
# 12: Cornacchia
####

chall12 = Problem()

# (45, 17) or (21, 19)
d12_1 = 22
N12_1 = 8383
# (729485423, 689247146)
d12_2 = 608268054
N12_2 = 288964812689493391976023993
# (822249775978922834074863312050877571308123090437, 748784818951812933713395251176142145550673582079)
d12_3 = 809575361919189873249985593557526797315607233589
N12_3 = 453911665595804740746927043910783828583622477123414312540919542168796850447209357992143785144169862380534061054229556425568794584043785497763918


chall12_checker1 = lambda ans: 0 < ans[0] < 100 and 0 < ans[1] < 100 and ans[0]**2 + d12_1 * ans[1]**2 == N12_1
chall12_checker2 = lambda ans: 0 < ans[0] < 10**10 and 0 < ans[1] < 10**10 and ans[0]**2 + d12_2 * ans[1]**2 == N12_2
chall12_checker3 = lambda ans: 0 < ans[0] < 10**50 and 0 < ans[1] < 10**50 and ans[0]**2 + d12_3 * ans[1]**2 == N12_3

chall12.append(
     "LEVEL 1: find positive integers x, y that solve x^2 + " + str(d12_1) + "*y^2 = " + str(N12_1)
    , chall12_checker1, 2)
chall12.append(
     "LEVEL 2: find positive integers x, y that solve x^2 + " + str(d12_2) + "*y^2 = " + str(N12_2)
    , chall12_checker2, 2)
chall12.append(
     "LEVEL 3: find positive integers x, y that solve x^2 + a*y^2 = b, where\n\n"
     "  a = " + str(d12_3) + "\n"
     "  b = " + str(N12_3)
    , chall12_checker3, 2)


###
#13: polys in GF(2)
###

chall13 = Problem()

# 23 * 35 = 729
ans13_1 = 729
# 250062733632176 % 406399853 = 90071293
a13_2   = 250062733632176
b13_2   = 406399853
ans13_2 = 90071293 
#
a13_3 = 62988136202118127274037485756847228824659813916854388288704528975265641038375
b13_3 = 61970982425686765788241036465223359125124685363948286523458864616239704859380
c13_3 = 16032512672834824306563461964216557396271213056568232093692714812022221106419800157218922185040829131491280726002257183375575408421728567246659014589764356633340492085105583082470307172750166547566757359700457224812429817166783751
ans13_3 = 23460293004934044667628268721192809418561264738963529778769473665520855679803

chall13_checker1 = lambda ans: ans[0] == ans13_1
chall13_checker2 = lambda ans: ans[0] == ans13_2
chall13_checker3 = lambda ans: ans[0] == ans13_3



chall13.append(
     "LEVEL 1: consider polynomials in x with coefficients that are either 0 or 1.\n"
     "         Suppose we multiply two such polynomials the usual way, except that\n"
     "         in the result we substitute 0 for even coefficients, 1 for odd ones\n"
     "         (this just means that coefficients live in the Galois field GF(2)).\n"
     "         For example, (1+x)*(1+x) = 1+2*x+x^2 = 1+x^2.\n"
     "            We can also map such polynomials to integers by simply taking the\n"
     "         coefficients as a bit string. E.g., 1+x+x^4 = 1+x+0*x^2+0*x^3+x^4\n"
     "         = 11001 in binary, which is 19 in decimal. Give the integer that is\n"
     "         the result of the multiplication 35*23 in this setup."
    , chall13_checker1, 1)
chall13.append(
     "LEVEL 2: consider the construction introduced in Level 1. Compute the\n"
     "         remainder when " + str(a13_2) + " is divided by " + str(b13_2) + ".\n"
     "         I.e., convert the integers to polynomials, do the division,\n"
     "         and convert the result back to an integer.\n"
     "         (You can RESET the problem if you forgot what was in Level 1)"
    , chall13_checker2, 1)
chall13.append(
     "LEVEL 3: consider the construction introduced in Level 1 that mapped\n"
     "         polynomials to integers. Find the solution to the equation\n"
     "         a*y^2 + b*y + c = 0 in that setup, where\n\n"
     "  a = " + str(a13_3) + "\n"
     "  b = " + str(b13_3) + "\n"
     "  c = " + str(c13_3)
    , chall13_checker3, 1)



####
# 14: wizard lab
####

chall14 = Problem()

# 100 digits of pi
chall14_ans = 3141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117067

assert len(str(chall14_ans)) == 100, "len(chall4_ans)=" + str(len(str(chall14_ans)))


chall14_checker = lambda ans: ans[0] == chall14_ans

chall14.append("EASY AS PIE: give the first 100 digits of pi", chall14_checker, 1)


####
# empty
####

chall_none = Problem()


####
#dummy
####

chall_dummy = Problem()
chall_dummy_checker1 = lambda ans: ans[0] == 3 

chall_dummy.append("LEVEL 1: Add 1 and 2.", chall_dummy_checker1, 1)


#
# append everything to the list
#
challenges.append(chall5)      #0
challenges.append(chall3)      #1
challenges.append(chall1)      #2
challenges.append(chall0)      #3
challenges.append(chall6)      #4
challenges.append(chall14)     #5
challenges.append(chall4)      #6
challenges.append(chall2)      #7
challenges.append(chall7)      #8
challenges.append(chall9)      #9
challenges.append(chall11)     #10
challenges.append(chall10)     #11
challenges.append(chall8)      #12
challenges.append(chall_none)  #13
challenges.append(chall12)     #14
challenges.append(chall13)     #15



if __name__ == "__main__":
   print( [ chall1.isCorrect([i], 0)   for i in range(10) ] )
   print( [ chall1.isCorrect([i], 1)   for i in range(10) ] )
   print( [ chall1.isCorrect([i], 2)   for i in range(10) ] )
   print( [ chall1.isCorrect([i], 3)   for i in range(10) ] )


