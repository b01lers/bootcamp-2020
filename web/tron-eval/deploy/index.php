<?php
    $packet = new stdClass();
    $packet->version = "6.5";
    $packet->ihl = 0;
    $packet->len = 0;
    $packet->ttl = 1;

    if(isset($_COOKIE["seqno"])) {
        $packet->seqno = intval($_COOKIE["seqno"]) + 1;
    } else {
        $packet->seqno = 0;
    }
    setcookie("seqno", $packet->seqno, time() + (86400 * 30), "/");

    if(isset($_COOKIE["ackno"])) {
        $packet->ackno = intval($_COOKIE["ackno"]) + 1;
    } else {
        $packet->ackno = 1;
    }
    setcookie("ackno", $packet->ackno, time() + (86400 * 30), "/");

    $packet->algo = "sha256";
    $packet->checksum = "";
    $packet->data = "";

    $json_packet = json_encode($packet, JSON_HEX_QUOT);
?>

<!DOCTYPE html>
<html>
    <head>
        <title>Protocol v6.5</title>
        <link rel="stylesheet" href="/style.css"/>
        <link rel="stylesheet" href="/tron.css"/>
        <script src="/sjcl.js"></script>
        <script>
            function update_len(packet, stringify){
                while(stringify.length + 64 != packet.len){
                    // 64 from length of sha256 checksum
                    packet.len = stringify.length + 64;
                    let ihl = packet.version.length + packet.len.toString().length + packet.ttl.toString().length + packet.seqno.toString().length + packet.ackno.toString().length + packet.algo.length + 64;
                    packet.ihl = ihl + ihl.toString().length;
                    stringify = JSON.stringify(packet);
                    console.log(stringify, stringify.length + 64);
                }
                return packet;
            }

            function submit_packet() {
                let packet = JSON.parse(document.getElementById("packet").value);
                packet.data = document.getElementById("data").value;
                let stringify = JSON.stringify(packet);

                packet = update_len(packet, stringify);

                let hash = new sjcl.hash.sha256();
                hash.update((packet.ihl + packet.len + packet.ttl + packet.seqno + packet.ackno).toString());
                packet.checksum = sjcl.codec.hex.fromBits(hash.finalize());

                stringify = JSON.stringify(packet);
                document.getElementById("packet").value = stringify;
                document.getElementById("data_form").submit();
            }
        </script>
    </head>
    <body>
        <div id="main-wrapper">
            <div class="content-page">
                <div>
                    <h1>Next Gen Networking Demo</h1>
                </div>
                <div>
                    <textarea id="data" form="data_form" rows=4 cols=50>Enter data here...</textarea>
                    <form action="/packets/send.php" id="data_form" method="post">
                        <button type="button" onclick="submit_packet()">Send packet</button>
                        <input type="hidden" id="packet" name="packet" value='<?=$json_packet ?>'>
                    </form>
                </div>
            </div>
        </div>
    </body>
</html>
