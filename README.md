# Big Brother Surveilance
## About the code
BigBrother surveilance is a tool in development with the ultimate goal of not relying on cloud services for your video doorbell. It is in active development. Currently, the following is supported:
- Reolink support (up to a certain extent). Much of the protocol reverse engineering was done by [Neolink](https://github.com/thirtythreeforty/neolink). Right now the implementation is capable of:
  - Logging in;
  - Sending ping messages;
  - Sending audio;
  - Detecting doorbell events (doorbell press, PIR detection, object movement).
 -Support for USB relays

There is a simple program (bb), that turn a relay on and off when somebody presses the doorbell.

## Installation
The following libraries are needed:
-Hidapi (operate relay);
-WolfSSL (certain cryptographic operations);
-Ivykis (asynchronous IO);
-Tomlc99 (parsing configuration files);
-Gstreamer (used for converting audio files to the right format, might go in future versions);
-Mxml (parsing and creation of XML messages used in the communication protocol);

On Ubuntu Tomlc99 is not supported and has to be downloaded and installed from [here](https://github.com/cktan/tomlc99)

To compile and install:
```
libtoolize
aclocal
autoconf
automake --add-missing
autoreconf
./configure
make
make install
```

## Usage
Using it is pretty straightforward
bb -c <configuration_file> 

A sample configuration file can be found in the test/ directory

## Roadmap
- [ ] Add support to send messages with the Wire client
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

## Contact ?
big_brother_is_watching_you shift 2 tutanota.com

