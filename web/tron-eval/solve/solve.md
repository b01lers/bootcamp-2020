# Next Gen Networking
- This is a hard php chall we get source for `send.php`, but we're not sure how it's used yet.

## index.php
- This file takes input and sends it to the `send.php` file that we're given.
- There's input for data and a send button and client side javascript so let's take a quick look at that.
- The `update_len` function just updates some values in an object, and the `send_packet` function sends the post data to `send.php`
```javascript
function submit_packet() {
    let packet = JSON.parse(document.getElementById("packet").value);
    packet.data = document.getElementById("data").value;
    let stringify = JSON.stringify(packet);

    packet = update_len(packet, stringify);

    let hash = new sjcl.hash.sha256();

    // This line is important
    hash.update((packet.ihl + packet.len + packet.ttl + packet.seqno + packet.ackno).toString());
    // ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    packet.checksum = sjcl.codec.hex.fromBits(hash.finalize());

    stringify = JSON.stringify(packet);
    document.getElementById("packet").value = stringify;
    document.getElementById("data_form").submit();
```
- Most of this function isn't interesting, but the hash calculation is something to take note of.

## send.php
- Let's see what happens when we send a packet.
- Hitting the send button we get `Packet data written` and a link to our data.
- This is interesting, we're able to write to the server, and we get a path!
- Important lines in `send.php` are:
```php
if($packet->ihl != $calculated_ihl or $packet->ihl > 170) {
```
- This has a limit for the header length to be 170..

```php
if($packet->ackno != $_COOKIE["seqno"] + 1) {
    return "<p>Error: out of order packet</p>";
}
```
- This line is interesting because the comparison uses the `$_COOKIE` value instead of `$packet->seqno`. This can be used to input data into the seqno value.

```php
$checksum_str = "\$checksum = hash(\"$packet->algo\", strval($packet->ihl + $packet->len + $packet->ttl + $packet->seqno + $packet->ackno));";
eval($checksum_str);
```
- These next lines contain an `eval`.
- The secure php developer's guide is to **never use eval, ever**.
- This takes user input and we can control some of the inputs so let's break it.

## Code execution with eval()
- The eval string is: `$checksum_str = "\$checksum = hash(\"$packet->algo\", strval($packet->ihl + $packet->len + $packet->ttl + $packet->seqno + $packet->ackno));";`
- Our input is `$packet->seqno` and we've got to break out of the hash function with 2 ')'

### PHP debugging tips
1. We can check the eval using a local php instance of `send.php` and sending curl or postman requests to it.
1. `php -r 'echo "PHP!";'` will also let us debug our injection into eval.


### Breaking out
- A valid breakout input for seqno is: `));//`
- We can now call php functions after the `;` and before the `//`
- Now the 170 limit is going to become an issue... But we have write so we can write php to a file, then call that file during the eval.

### Putting it all together
- See [solve.py](solve.py) for the final code, but the theory is:
1. Send a valid request using the data field to store our php code we want to execute
    - This php code should start as a `ls` to find the flag, then a `cat`
    - 2 Ways of exfiltrating data are: callback to a server, or make another file and, then `cat` that
1. Send a request with the breakout seqno string that calls our packet file.
