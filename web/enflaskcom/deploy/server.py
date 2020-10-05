from flask import Flask, make_response, request
import pickle
import binascii
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA384


app = Flask(__name__)


class User:

    def is_admin(self):
        return False


def sign(msg):
    if type(msg) is not bytes:
        msg = bytes(msg, 'utf8')
    keyPair = RSA.RsaKey(n=122929120347181180506630461162876206124588624246894159983930957362668455150316050033925361228333120570604695808166534050128069551994951866012400864449036793525176147906281580860150210721340627722872013368881325479371258844614688187593034753782177752358596565495566940343979199266441125486268112082163527793027, e=65537, d=51635782679667624816161506479122291839735385241628788060448957989505448336137988973540355929843726591511533462854760404030556214994476897684092607183504108409464544455089663435500260307179424851133578373222765508826806957647307627850137062790848710572525309996924372417099296184433521789646380579144711982601, p=9501029443969091845314200516854049131202897408079558348265027433645537138436529678958686186818098288199208700604454521018557526124774944873478107311624843, q=12938505355881421667086993319210059247524615565536125368076469169929690129440969655350679337213760041688434152508579599794889156578802099893924345843674089, u=3286573208962127166795043977112753146960511781843430267174815026644571470787675370042644248296438692308614275464993081581475202509588447127488505764805156)
    signer = pkcs1_15.new(keyPair)
    hsh = SHA384.new()
    hsh.update(msg)
    signature = signer.sign(hsh)

    return signature


@app.route('/')
def hello_world():
    resp = make_response('Flag is at /flag. Don\'t bother with a reverse shell.')
    msg = binascii.hexlify(pickle.dumps(User()))
    signature = binascii.hexlify(sign(msg))

    resp.set_cookie('user', msg)
    resp.set_cookie('signature', signature)

    return resp


@app.route('/flag')
def flag():
    signature = binascii.unhexlify(request.cookies.get("signature"))
    checkme = sign(request.cookies.get("user"))
    print(signature)
    print(checkme)
    assert signature == checkme

    user = pickle.loads(binascii.unhexlify(request.cookies.get("user")))

    if user.is_admin():
        with open('flag.txt', 'r') as f:
            text = f.read()
        resp = make_response(text)
        return resp
    else:
        resp = make_response("You need to be admin")
        return resp


if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)