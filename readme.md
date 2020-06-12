# 2020-04-28

# Misc
* Android client in Kotlin
* Server in Python
* Linux-CLI in Python
* repo on github

# Message
* sender_id
* timestamp
* command
  * send notification
  * request authorization
* message title, message body


## Protocol
* Running over HTTPS/JSON
* Recipient receives Wakeup-Event
* Recipient uses `sync` api call to get actual messages
* be careful about replay attacks
