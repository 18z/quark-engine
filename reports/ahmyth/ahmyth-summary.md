# Ahmyth rule hits

Generated from `ahmyth-report.json`. Rule ids and labels only.

Sample SHA256: `f39b1a25c299ff532df840c6216fee41c8eb70787aba5e51624aae7b8eccc12c`
Rules commit: `a9fb558fae4c9d23f325289396c06d7c5e519318`
Hit count: 42

- 00001 [camera] Initialize bitmap object and compress data (e.g. JPEG) into bitmap object
- 00002 [camera] Open the camera and take picture
- 00004 [file, collection] Get filename and put it to JSON object
- 00005 [file] Get absolute path of file and put it to JSON object
- 00007 [file] Use absolute path of directory for the output media file path
- 00008 [sms] Check if successfully sending out SMS
- 00009 [file] Put data in cursor to JSON object
- 00010 [sms, calllog, collection] Read sensitive data(SMS, CALLLOG) and put it into JSON object
- 00011 [sms, calllog, collection] Query data from URI (SMS, CALLLOGS)
- 00012 [file] Read data and put it into a buffer stream
- 00013 [file] Read file and put it into a stream
- 00014 [file] Read file into a stream and put it into a JSON object
- 00015 [file] Put buffer stream (data) to JSON object
- 00017 [location, collection] Get Location of the device and append this info to a string
- 00019 [reflection] Find a method from given class name, usually for reflection
- 00026 [reflection] Method reflection
- 00029 [reflection] Initialize class object dynamically
- 00077 [collection, sms, calllog, calendar] Read sensitive data(SMS, CALLLOG, etc)
- 00108 [network, command] Read the input stream from given URL
- 00115 [collection, location] Get last known location of the device
- 00157 [reflection, dexClassLoader] Instantiate new object using reflection, possibly used for dexClassLoader
- 00182 [camera] Open camera.
- 00185 [camera] Start capturing camera preview frames to the screen
- 00186 [camera] Control camera to take picture
- 00187 [collection, sms, calllog, calendar] Query a URI and check the result
- 00188 [sms] Get the address of a SMS message
- 00189 [sms] Get the content of a SMS message
- 00191 [sms] Get messages in the SMS inbox
- 00192 [sms] Get messages in the SMS inbox
- 00193 [sms] Send a SMS message
- 00194 [record] Set the audio source (MIC) and recorded file format
- 00195 [record, file] Set the output path of the recorded file
- 00196 [record, file] Set the recorded file format and output path
- 00197 [record] Set the audio encoder and initialize the recorder
- 00198 [record] Initialize the recorder and start recording
- 00199 [record] Stop recording and release recording resources
- 00201 [collection, calllog] Query data from the call log
- 00212 [collection] Query device data with ContentResolver
- 00230 [control] Start a background service
- 00269 [screen] Compress bitmap
- 00272 [reflection, evasion] Resolve field via reflection
- 00276 [reflection] Invoke method dynamically via reflection
