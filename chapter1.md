1 - The DNS protocol
====================

We'll start out by investigating the DNS protocol and use our knowledge thereof
to implement a simple client.

Conventionally, DNS packets are sent using UDP transport and are limited to 512
bytes. As we'll see later, both of those rules have exceptions: DNS can be used
over TCP as well, and using a mechanism known as eDNS we can extend the packet
size. For now, we'll stick to the original specification, though.

DNS is quite convenient in the sense that queries and responses use the same
format. This means that once we've written a packet parser and a packet writer,
our protocol work is done. This differs from most Internet Protocols, which
typically use different request and response structures. On a high level, a DNS
packet looks as follows:

| Section            | Size     | Type              | Purpose                                                                                                |
| ------------------ | -------- | ----------------- | ------------------------------------------------------------------------------------------------------ |
| Header             | 12 Bytes | Header            | Information about the query/response.                                                                  |
| Question Section   | Variable | List of Questions | In practice only a single question indicating the query name (domain) and the record type of interest. |
| Answer Section     | Variable | List of Records   | The relevant records of the requested type.                                                            |
| Authority Section  | Variable | List of Records   | An list of name servers (NS records), used for resolving queries recursively.                          |
| Additional Section | Variable | List of Records   | Additional records, that might be useful. For instance, the corresponding A records for NS records.    |

Essentially, we have to support three different objects: Header, Question and
Record. Conveniently, the lists of records and questions are simply individual
instances appended in a row, with no extras. The number of records in each
section is provided by the header. The header structure looks as follows:

| RFC Name | Descriptive Name     | Length             | Description                                                                                                                                                                         |
| -------- | -------------------- | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID       | Packet Identifier    | 16 bits            | A random identifier is assigned to query packets. Response packets must reply with the same id. This is needed to differentiate responses due to the stateless nature of UDP.       |
| QR       | Query Response       | 1 bit              | 0 for queries, 1 for responses.                                                                                                                                                     |
| OPCODE   | Operation Code       | 4 bits             | Typically always 0, see RFC1035 for details.                                                                                                                                        |
| AA       | Authoritative Answer | 1 bit              | Set to 1 if the responding server is authoritative - that is, it "owns" - the domain queried.                                                                                       |
| TC       | Truncated Message    | 1 bit              | Set to 1 if the message length exceeds 512 bytes. Traditionally a hint that the query can be reissued using TCP, for which the length limitation doesn't apply.                     |
| RD       | Recursion Desired    | 1 bit              | Set by the sender of the request if the server should attempt to resolve the query recursively if it does not have an answer readily available.                                     |
| RA       | Recursion Available  | 1 bit              | Set by the server to indicate whether or not recursive queries are allowed.                                                                                                         |
| Z        | Reserved             | 3 bits             | Originally reserved for later use, but now used for DNSSEC queries.                                                                                                                 |
| RCODE    | Response Code        | 4 bits             | Set by the server to indicate the status of the response, i.e. whether or not it was successful or failed, and in the latter case providing details about the cause of the failure. |
| QDCOUNT  | Question Count       | 16 bits            | The number of entries in the Question Section                                                                                                                                       |
| ANCOUNT  | Answer Count         | 16 bits            | The number of entries in the Answer Section                                                                                                                                         |
| NSCOUNT  | Authority Count      | 16 bits            | The number of entries in the Authority Section                                                                                                                                      |
| ARCOUNT  | Additional Count     | 16 bits            | The number of entries in the Additional Section                                                                                                                                     |

The question is quite a bit less scary:

| Field  | Type           | Description                                                          |
| ------ | -------------- | -------------------------------------------------------------------- |
| Name   | Label Sequence | The domain name, encoded as a sequence of labels as described below. |
| Type   | 2-byte Integer | The record type.                                                     |
| Class  | 2-byte Integer | The class, in practice always set to 1.                              |

The tricky part lies in the encoding of the domain name, which we'll return to
later.

Finally, we've got the records which are the meat of the protocol. Many record
types exists, but for now we'll only consider a few essential. All records have
the following preamble:

| Field  | Type           | Description                                                                       |
| ------ | -------------- | --------------------------------------------------------------------------------- |
| Name   | Label Sequence | The domain name, encoded as a sequence of labels as described below.              |
| Type   | 2-byte Integer | The record type.                                                                  |
| Class  | 2-byte Integer | The class, in practice always set to 1.                                           |
| TTL    | 4-byte Integer | Time-To-Live, i.e. how long a record can be cached before it should be requeried. |
| Len    | 2-byte Integer | Length of the record type specific data.                                          |

Now we are all set to look a specific record types, and we'll start with the
most essential: the A record, mapping a name to an ip.

| Field      | Type            | Description                                                                       |
| ---------- | --------------- | --------------------------------------------------------------------------------- |
| Preamble   | Record Preamble | The record preamble, as described above, with the length field set to 4.          |
| IP         | 4-byte Integer  | An IP-address encoded as a four byte integer.                                      |

Having gotten this far, let's get a feel for this in practice by performing
a lookup using the `dig` tool:

```text
# dig +noedns google.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +noedns google.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 36383
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;google.com.                    IN      A

;; ANSWER SECTION:
google.com.             204     IN      A       172.217.18.142

;; Query time: 0 msec
;; SERVER: 192.168.1.1#53(192.168.1.1)
;; WHEN: Wed Jul 06 13:24:19 CEST 2016
;; MSG SIZE  rcvd: 44
```

We're using the `+noedns` flag to make sure we stick to the original format.
There are a few things of note in the output above:

 * We can see that `dig` explicitly describes the header, question and answer
   sections of the response packet.
 * The header is using the OPCODE QUERY which corresponds to 0. The status
   (RESCODE) is set to NOERROR, which is 0 numerically. The id is 36383, and
   will change randomly with repeated queries. The Query Response (qr),
   Recursion Desired (rd), Recursion Available (ra) flags are enabled, which are 
   1 numerically. We can ignore `ad` for now, since it relates to DNSSEC. Finally, 
   the header tells us that there is one question and one answer record.
 * The question section shows us our question, with the `IN` indicating the
   class, and A telling us that we're performing a query for A records.
 * The answer section contains the answer record, with google's IP. `204` is the
   TTL, IN is again the class, and A is the record type. Finally, we've got the
   google.com IP-address.
 * The final line tells us that the total packet size was 44 bytes.

There are still some details obscured from view here though, so let's dive
deeper still and look at a hexdump of the packets. We can use `netcat` to listen
on a port, and then direct `dig` to send the query there. In one terminal
window we run:

```text
# nc -u -l 1053 > query_packet.txt
```

Then in another window, do:

```text
# dig +retry=0 -p 1053 @127.0.0.1 +noedns google.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +retry=0 -p 1053 @127.0.0.1 +noedns google.com
; (1 server found)
;; global options: +cmd
;; connection timed out; no servers could be reached
```

The failure is expected in this case, since `dig` will timeout when it doesn't
receive a response. Since this fails, it exits. At this point `netcat` can be
exited using Ctrl+C. We're left with a query packet in `query_packet.txt`. We can use our
query packet to record a response packet as well:

```text
# nc -u 8.8.8.8 53 < query_packet.txt > response_packet.txt
```

Give it a second, and the cancel using Ctrl+C. We are now ready to inspect our
packets:

```text
# hexdump -C query_packet.txt
00000000  86 2a 01 20 00 01 00 00  00 00 00 00 06 67 6f 6f  |.*. .........goo|
00000010  67 6c 65 03 63 6f 6d 00  00 01 00 01              |gle.com.....|
0000001c
# hexdump -C response_packet.txt
00000000  86 2a 81 80 00 01 00 01  00 00 00 00 06 67 6f 6f  |.*...........goo|
00000010  67 6c 65 03 63 6f 6d 00  00 01 00 01 c0 0c 00 01  |gle.com.........|
00000020  00 01 00 00 01 25 00 04  d8 3a d3 8e              |.....%...:..|
0000002c
```

Let's see if we can make some sense of this. We know from earlier that the
header is 12 bytes long. For the query packet, the header bytes are:
`86 2a 01 20 00 01 00 00 00 00 00 00` We can see that the last eight bytes
corresponds to the length of the different sections, with the only one actually
having any content being the question section which holds a single entry. The
more interesting part is the first four bytes, which corresponds to the
different fields of the header. First off, we know that we've got a 2-byte
id, which is supposed to stay the same for both query and answer. Indeed we
see that in this example it's set to `86 2a` in both hexdumps. The hard part
to parse is the remaining two bytes. In order to make sense of them, we'll have
to convert them to binary. Starting with the `01 20` of the query packet, we
find (with the Most Significant Bit first):

```text
0 0 0 0 0 0 0 1  0 0 1 0 0 0 0 0
- -+-+-+- - - -  - -+-+- -+-+-+-
Q    O    A T R  R   Z      R
R    P    A C D  A          C
     C                      O
     O                      D
     D                      E
     E
```

Except for the DNSSEC related bit in the `Z` section, this is as expected. `QR`
is 0 since its a Query, `OPCODE` is also 0 since it's a standard lookup, the
`AA`, `TC` and `RA` flags isn't relevant for queries while `RD` is set, since `dig`
defaults to requesting recursive lookup. Finally, `RCODE` isn't used for
queries either.

Moving on to the flag bytes of the response packet `81 80`:

```text
1 0 0 0 0 0 0 1  1 0 0 0 0 0 0 0
- -+-+-+- - - -  - -+-+- -+-+-+-
Q    O    A T R  R   Z      R
R    P    A C D  A          C
     C                      O
     O                      D
     D                      E
     E
```

Since this is a response `QR` is set, and so is `RA` to indicate that the
server does support recursion. Looking at the remaining eight bytes of the reply,
we see that in addition to having a single question, we've also got a single
answer record.

Immediately past the header, we've got the question. Let's break it down byte
by byte:

```text
                    query name              type   class
       -----------------------------------  -----  -----
HEX    06 67 6f 6f 67 6c 65 03 63 6f 6d 00  00 01  00 01
ASCII     g  o  o  g  l  e     c  o  m
DEC    6                    3           0       1      1
```

As outlined in the table earlier, it consists of three parts: query name, type
and class. There's something interesting about the how the name is encoded,
though -- there are no dots present. Rather DNS encodes each name into
a sequence of `labels`, with each label prepended by a single byte indicating
its length. In the example above, "google" is 6 bytes and is thus preceded by
`0x06`, while "com" is 3 bytes and is preceded by `0x03`. Finally, all names
are terminated by a label of zero length, that is a null byte. Seems easy
enough, doesn't it? Well, as we shall see soon there's another twist to it.

We've now reached the end of our query packet, but there is some data left to
decode in the response packet. The remaining data is a single A record holding
the corresponding IP address for google.com:

```text
      name     type   class         ttl        len      ip
      ------  ------  ------  --------------  ------  --------------
HEX   c0  0c  00  01  00  01  00  00  01  25  00  04  d8  3a  d3  8e
DEC   192 12    1       1           293         4     216 58  211 142
```

Most of this is as expected: Type is 1 for `A record`, Class is 1 for `IN`, TTL
in this case is 293 which seems reasonable, the data length is 4 which is as it
should, and finally we learn that the IP of google is `216.58.211.142`. What
then is going on with the name field? Where are the labels we just learned
about?

Due to the original size constraints of DNS, of 512 bytes for a single packet,
some type of compression was needed. Since most of the space required is for
the domain names, and part of the same name tends to reoccur, there's some
obvious space saving opportunity. For example, consider the following DNS
query:

```text
# dig @a.root-servers.net com

- snip -

;; AUTHORITY SECTION:
com.                172800  IN  NS      e.gtld-servers.net.
com.                172800  IN  NS      b.gtld-servers.net.
com.                172800  IN  NS      j.gtld-servers.net.
com.                172800  IN  NS      m.gtld-servers.net.
com.                172800  IN  NS      i.gtld-servers.net.
com.                172800  IN  NS      f.gtld-servers.net.
com.                172800  IN  NS      a.gtld-servers.net.
com.                172800  IN  NS      g.gtld-servers.net.
com.                172800  IN  NS      h.gtld-servers.net.
com.                172800  IN  NS      l.gtld-servers.net.
com.                172800  IN  NS      k.gtld-servers.net.
com.                172800  IN  NS      c.gtld-servers.net.
com.                172800  IN  NS      d.gtld-servers.net.

;; ADDITIONAL SECTION:
e.gtld-servers.net. 172800  IN  A       192.12.94.30
b.gtld-servers.net. 172800  IN  A       192.33.14.30
b.gtld-servers.net. 172800  IN  AAAA    2001:503:231d::2:30
j.gtld-servers.net. 172800  IN  A       192.48.79.30
m.gtld-servers.net. 172800  IN  A       192.55.83.30
i.gtld-servers.net. 172800  IN  A       192.43.172.30
f.gtld-servers.net. 172800  IN  A       192.35.51.30
a.gtld-servers.net. 172800  IN  A       192.5.6.30
a.gtld-servers.net. 172800  IN  AAAA    2001:503:a83e::2:30
g.gtld-servers.net. 172800  IN  A       192.42.93.30
h.gtld-servers.net. 172800  IN  A       192.54.112.30
l.gtld-servers.net. 172800  IN  A       192.41.162.30
k.gtld-servers.net. 172800  IN  A       192.52.178.30
c.gtld-servers.net. 172800  IN  A       192.26.92.30
d.gtld-servers.net. 172800  IN  A       192.31.80.30

- snip -
```

Here we query one of the internet root servers for the name servers handling
the .com TLD. Notice how `gtld-servers.net.` keeps reappearing -- wouldn't it
be convenient if we'd only have to include it once? One way to achieve this is
to include a "jump directive", telling the packet parser to jump to another
position, and finish reading the name there. As it turns out, that's exactly
what we're looking at in our response packet.

I mentioned earlier that each label is preceeded by a single byte length. The
additional thing we need to consider is that if the two Most Significant Bits of
the length is set, we can instead expect the length byte to be followed by
a second byte. These two bytes taken together, and removing the two MSB's, indicate
the jump position. In the example above, we've got `0xC00C`. The bit pattern of
the the two high bits expressed as hex is `0xC000` (in binary `11000000
00000000`), so we can find the jump position by xoring our two bytes with this
mask to unset them: `0xC00C ^ 0xC000 = 12`. Thus we should jump to byte 12 of
the packet and read from there. Recalling that the length the DNS header
happens to be 12 bytes, we realize that it's instructing us to start reading
from where the question part of the packet begins, which makes sense since the
question starts with the query domain which in this case is "google.com". Once
we've finished reading the name, we resume parsing where we left off, and move
on to the record type.

### BytePacketBuffer

Now finally we know enough to start implementing! The first order of business is
that we need some convenient method for manipulating the packets. For this,
we'll use a `struct` called `BytePacketBuffer`.

```rust
pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {

    /// This gives us a fresh buffer for holding the packet contents, and a
    /// field for keeping track of where we are.
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    /// Current position within buffer
    fn pos(&self) -> usize {
        self.pos
    }

    /// Step the buffer position forward a specific number of steps
    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }

    /// Change the buffer position
    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    /// Read a single byte and move the position one step forward
    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Get a single byte, without changing the buffer position
    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err("End of buffer".into());
        }
        Ok(self.buf[pos])
    }

    /// Get a range of bytes
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err("End of buffer".into());
        }
        Ok(&self.buf[start..start + len as usize])
    }

    /// Read two bytes, stepping two steps forward
    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    /// Read four bytes, stepping four steps forward
    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }


    /// Read a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within the struct. This
        // allows us to move the shared position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        let mut pos = self.pos();

        // track whether or not we've jumped
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        // Our delimiter which we append for each label. Since we don't want a
        // dot at the beginning of the domain name we'll leave it empty for now
        // and set it to "." at the end of the first iteration.
        let mut delim = "";
        loop {
            // Dns Packets are untrusted data, so we need to be paranoid. Someone
            // can craft a packet with a cycle in the jump instructions. This guards
            // against such packets.
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            // At this point, we're always at the beginning of a label. Recall
            // that labels start with a length byte.
            let len = self.get(pos)?;

            // If len has the two most significant bit are set, it represents a
            // jump to some other offset in the packet:
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current
                // label. We don't need to touch it any further.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate offset and perform the jump by
                // updating our local position variable
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indicate that a jump was performed.
                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // The base scenario, where we're reading a single label and
            // appending it to the output:
            else {
                // Move a single byte forward to move past the length byte.
                pos += 1;

                // Domain names are terminated by an empty label of length 0,
                // so if the length is zero we're done.
                if len == 0 {
                    break;
                }

                // Append the delimiter to our output buffer first.
                outstr.push_str(delim);

                // Extract the actual ASCII bytes for this label and append them
                // to the output buffer.
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Move forward the full length of the label.
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}
```

### ResultCode

Before we move on to the header, we'll add an enum for the values of `rescode` field:

```rust
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}
```

### DnsHeader

Now we can get to work on the header. We'll represent it like this:

```rust
#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}
```

The implementation involves a lot of bit twiddling:

```rust
impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }
}
```

### QueryType

Before moving on to the question part of the packet, we'll need a way to
represent the record type being queried:

```rust
#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A, // 1
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num),
        }
    }
}
```

### DnsQuestion

The enum allows us to easily add more record types later on. Now for the
question entries:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion {
            name: name,
            qtype: qtype,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class

        Ok(())
    }
}
```

Having done the hard part of reading the domain names as part of our
`BytePacketBuffer` struct, it turns out to be quite compact.

### DnsRecord

We'll obviously need a way of representing the actual dns records as well, and
again we'll use an enum for easy expansion:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
}
```

Since there are many types of records, we'll add the ability to keep track of
record types we haven't yet encountered. The enum will also allow us to easily
add new records later on. The actual implementation of `DnsRecord` looks like
this:

```rust
impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(DnsRecord::A {
                    domain: domain,
                    addr: addr,
                    ttl: ttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::UNKNOWN {
                    domain: domain,
                    qtype: qtype_num,
                    data_len: data_len,
                    ttl: ttl,
                })
            }
        }
    }
}
```

### DnsPacket

Finally, let's put it all together in a struct called `DnsPacket`:

```rust
#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }
}
```

### Putting it all together

Let's use the `response_packet.txt` we generated earlier to try it out!

```rust
fn main() -> Result<()> {
    let mut f = File::open("response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();
    f.read(&mut buffer.buf)?;

    let packet = DnsPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
```

Running it will print:

```text
DnsHeader {
    id: 34346,
    recursion_desired: true,
    truncated_message: false,
    authoritative_answer: false,
    opcode: 0,
    response: true,
    rescode: NOERROR,
    checking_disabled: false,
    authed_data: false,
    z: false,
    recursion_available: true,
    questions: 1,
    answers: 1,
    authoritative_entries: 0,
    resource_entries: 0
}
DnsQuestion {
    name: "google.com",
    qtype: A
}
A {
    domain: "google.com",
    addr: 216.58.211.142,
    ttl: 293
}
```

In the next chapter, we'll add network connectivity: [Chapter 2 - Building a stub resolver](/chapter2.md)
