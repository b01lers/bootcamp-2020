window.onload = function() {
    let input = document.getElementById("chat");
    input.focus();
    input.onkeypress = function send(e) {
        if (e.key === "Enter") {
            let message = "<li>" + input.value + "</li>";
            document.getElementById("messages").innerHTML += message;
            
        }
    }
}

window.onclick = function () {
    document.getElementById("chat").focus();
}

// don't waste your time with this
var _0x2e2c=['\x74\x72\x69\x67\x67\x65\x72','\x6f\x6b\x62\x75\x74\x74\x6f\x6e\x63\x6c\x69\x63\x6b\x65\x64','\x67\x65\x74\x45\x6c\x65\x6d\x65\x6e\x74\x42\x79\x49\x64','\x66\x6c\x61\x67\x7b\x79\x30\x75\x5f\x73\x68\x30\x75\x6c\x64\x6e\x74\x5f\x68\x34\x76\x33\x5f\x63\x30\x6d\x33\x5f\x62\x34\x63\x6b\x5f\x66\x6c\x79\x6e\x6e\x7d','\x6a\x51\x75\x65\x72\x79','\x61\x6c\x65\x72\x74'];(function(_0x4a3766,_0x6d4dbb){var _0x277919=function(_0x4f968d){while(--_0x4f968d){_0x4a3766['\x70\x75\x73\x68'](_0x4a3766['\x73\x68\x69\x66\x74']());}};_0x277919(++_0x6d4dbb);}(_0x2e2c,-0x1a8d+-0x2*0x9f+-0x1*-0x1c45));var _0xd7f1=function(_0x4a3766,_0x6d4dbb){_0x4a3766=_0x4a3766-(-0x1a8d+-0x2*0x9f+-0x1*-0x1bcb);var _0x277919=_0x2e2c[_0x4a3766];return _0x277919;};var _0x4f89d1=_0xd7f1;window[_0x4f89d1('\x30\x78\x33')]=function(_0x36059f,_0x256ac9){return function(_0x5cbfad){var _0x2fc60f=_0xd7f1;_0x36059f(_0x5cbfad),_0x256ac9(window)[_0x2fc60f('\x30\x78\x34')]('\x6f\x6b\x62\x75\x74\x74\x6f\x6e\x63\x6c\x69\x63\x6b\x65\x64');};}(window[_0x4f89d1('\x30\x78\x33')],window[_0x4f89d1('\x30\x78\x32')]),$(window)['\x6f\x6e'](_0x4f89d1('\x30\x78\x35'),function(){var _0x452fbb=_0x4f89d1;document[_0x452fbb('\x30\x78\x30')]('\x72\x65\x73\x75\x6c\x74')['\x69\x6e\x6e\x65\x72\x54\x65\x78\x74']=_0x452fbb('\x30\x78\x31');});