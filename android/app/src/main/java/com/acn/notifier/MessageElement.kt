package com.acn.notifier

class MessageElement {

    var from:String = "";
    var message:String = "";
    var footer:String = "";

    constructor(setFrom:String, setMessage:String, setFooter:String) {
        from = setFrom;
        message = setMessage;
        footer = setFooter;
    }
}