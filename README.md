# Big Brother Surveilance
## About the code
BigBrother surveilance is a tool in development with the ultimate goal of not relying on cloud services for your video doorbell. It is in active development. Currently, the following is supported:
- Reolink support (up to a certain extent). Much of the protocol reverse engineering was done by [Neolink](https://github.com/thirtythreeforty/neolink). Right now the implementation is capable of:
  - Logging in;
  - Sending ping messages;
  - Sending audio;
  - Detecting doorbell events (doorbell press, PIR detection, object movement).
 -Support for USB relays
 -Wire, send messages

There is a simple program (bb), that turn a relay on and off when somebody presses the doorbell and sends a message to the wire channel (if configured)

## Installation
The following libraries are needed:
-Hidapi (operate relay);
-WolfSSL (certain cryptographic operations);
-Ivykis (asynchronous IO);
-Tomlc99 (parsing configuration files);
-Gstreamer (used for converting audio files to the right format, might go in future versions);
-Mxml (parsing and creation of XML messages used in the communication protocol);
-Wire-AVS

On Ubuntu Tomlc99 is not supported and has to be downloaded and installed from [here](https://github.com/cktan/tomlc99)

With the added Wire support, compiling got significantly more complex. First one needs to downloads Wire-avs from [here](https://github.com/wireapp/wire-avs). Clang13 should be used to compile and install it according to the instructions found in the README.md file. The configure command also got more complex. Filled in are some sample values, but please adjust them according to your setup. Also note that Wire depends on BoringSSL for certain functionality. Some of the libs in the configure command are not needed at the time, but most likely in the future, hence they are in there. 

To compile and install:
```
libtoolize
aclocal
autoconf
automake --add-missing
autoreconf
./configure CPPFLAGS="-DHAVE_PROTOBUF -DHAVE_CRYPTOBOX -DHAVE_READLINE" CFLAGS="-I/your_location/wire-avs/include -I/usr/include/gstreamer-1.0 -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -I/your_location/wire-avs/contrib/re/include/ -I/your_location/wire-avs/src/" LDFLAGS="-L/usr/local/lib64/ -L/your_location/wire-avs/build/linux-x86_64/lib/ -lavscore -ldl -lz -lpthread -lresolv -lre -lresolv -lrew -lre -lresolv -L/your_location/wire-avs/contrib/webrtc/20230222.69/lib/linux-x86_64 -lwebrtc -lcryptobox -lprotobuf-c  -lsodium -lreadline -lpthread -lprotobuf-c  -lcryptobox -lX11 -lXcomposite -lXdamage -lXext -lXfixes -lXrender -ldl -lrt -lm -lstdc++ -lpthread -lglib-2.0 -latomic "
make
make install
```

## Usage
If you decide to use wire, the following stepds need to be taken:
-Create an account for your doorbell;
-Create a channel with you and your doorbell in it;
-Send a message with the zcall client from Wire to the channel and make sure you receive it (this initializes the .zcall directory which is need by the lib).

Using it is pretty straightforward
bb -c <configuration_file> 

A sample configuration file can be found in the test/ directory

## Roadmap
- [x] Add support to send messages with the Wire client
- [ ] Add support to send images with the Wire client
- [ ] When a doorbell press is detected, send an image via Wire in a (group) chat
- [ ] Download the video stream via RTMP to a file as Reolink devices work best with RTMP
- [ ] Add support to send videos with the Wire client
- [ ] When a doorbell press is detected, send the video via Wire in a group chat by initiating a call
- [ ] Receive audio / video, via Wire when a call is accepted
- [ ] Send audio from the call to the doorbell
- [ ] ???

## Bugs ?
This code is not bug free or well tested, please report them and I'll fix them asap. 
There are some issues I encountered but was too lazy to fix (for now):
-Sometimes the login process doesn't work properly
-If connected for a long time, alarm messages aren't parsed properly anymore

I hope to fix those in future version.  

## Contact ?
big_brother_is_watching_you shift 2 tutanota.com

