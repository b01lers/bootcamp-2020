<?php
    function get_data() {
        if(!isset($_POST["packet"])){
            return "<p>Error: packet not found</p>";
        }

        $raw_packet = $_POST["packet"];
        $packet = json_decode($raw_packet);
        if($packet == null) {
            return "<p>Error: decoding packet</p>";
        }

        if($packet->version != 6.5) {
            return "<p>Error: wrong packet version</p>";
        }

        $calculated_ihl = strlen($packet->version) + strlen(strval($packet->len)) + strlen(strval($packet->ttl)) + strlen(strval($packet->seqno)) + strlen(strval($packet->ackno)) + strlen($packet->algo) + 64;
        $calculated_ihl = $calculated_ihl + strlen(strval($calculated_ihl));
        if($packet->ihl != $calculated_ihl or $packet->ihl > 170) {
            return "<p>Error: wrong header size</p>";
        }

        if($packet->len != strlen($raw_packet)) {
            return "<p>Error: mismatched packet size</p>";
        }

        if($packet->ttl - 1 != 0) {
            return "<p>Error: invalid ttl</p>";
        }

        if($packet->ackno != $_COOKIE["seqno"] + 1) {
            return "<p>Error: out of order packet</p>";
        }

        if($packet->algo != "sha256"){
            return "<p>Error: unsupported algorithm</p>";
        }

        $checksum_str = "\$checksum = hash(\"$packet->algo\", strval($packet->ihl + $packet->len + $packet->ttl + $packet->seqno + $packet->ackno));";
        eval($checksum_str);

        if($packet->checksum != $checksum) {
            return "<p>Error: checksums don't match</p>";
        }

        $file_name_hash = hash("md5", microtime());
        $file_name = "sent/".$file_name_hash.".packet";
        $packet_file = fopen($file_name, "w") or die("Unable to open packet file");
        fwrite($packet_file, $packet->data);
        fclose($packet_file);

        return "<h1>Packet data written</h1><div><a href=\"".$file_name."\">".$file_name_hash.".packet</a></div>";
    }
?>

<!DOCTYPE html>
<html>
    <head>
        <title>Send Packet.</title>
        <link rel="stylesheet" href="/style.css"/>
        <link rel="stylesheet" href="/tron.css"/>
    </head>
    <body>
        <div id="main-wrapper">
            <div class="content-page">
                <?php echo get_data(); ?>
            </div>
        </div>
    </body>
</html>
