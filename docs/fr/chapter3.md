3 - Ajouter d'autres types d'enregistrements
============================================

Utilisons notre programme pour résoudre *www.yahoo.com*.

```rust
let qname = "www.yahoo.com";
```

L'exécution donne :

```text
DnsHeader {
    id: 6666,
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
    answers: 3,
    authoritative_entries: 0,
    resource_entries: 0
}
DnsQuestion {
    name: "www.yahoo.com",
    qtype: A
}
UNKNOWN {
    domain: "www.yahoo.com",
    qtype: 5,
    data_len: 15,
    ttl: 259
}
A {
    domain: "fd-fp3.wg1.b.yahoo.com",
    addr: 46.228.47.115,
    ttl: 19
}
A {
    domain: "fd-fp3.wg1.b.yahoo.com",
    addr: 46.228.47.114,
    ttl: 19
}
```

Étrange : nous recevons un enregistrement UNKNOWN en plus de deux
enregistrements A. L'enregistrement UNKNOWN, de type 5, est un CNAME. Il existe
un bon nombre de types d'enregistrements DNS, dont beaucoup ne sont jamais
utilisés en pratique. Cela dit, examinons-en quelques-uns qui sont
essentiels :

| ID  | Nom   | Description                                                                  | Encodage                                                 |
| --- | ----- | ---------------------------------------------------------------------------- | -------------------------------------------------------- |
| 1   | A     | Alias - Associe des noms à des adresses IP                                   | Préambule + quatre octets pour l'adresse IPv4            |
| 2   | NS    | Serveur de noms (*Name Server*) - L'adresse du serveur DNS d'un domaine      | Préambule + suite de labels                              |
| 5   | CNAME | Nom canonique (*Canonical Name*) - Associe des noms à d'autres noms          | Préambule + suite de labels                              |
| 15  | MX    | Échangeur de courrier (*Mail eXchange*) - L'hôte du serveur mail d'un domaine | Préambule + 2 octets pour la priorité + suite de labels |
| 28  | AAAA  | Alias IPv6                                                                   | Préambule + seize octets pour l'adresse IPv6             |

### Étendre QueryType avec de nouveaux types d'enregistrements

Ajoutons-les à notre code ! Commençons par mettre à jour notre enum
`QueryType` :

```rust
#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,     // 1
    NS,    // 2
    CNAME, // 5
    MX,    // 15
    AAAA,  // 28
}
```

Il faut aussi modifier nos fonctions utilitaires.

```rust
impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num),
        }
    }
}
```

### Étendre DnsRecord pour lire les nouveaux types d'enregistrements

Il nous faut maintenant un moyen de stocker les données de ces
enregistrements ; nous allons donc apporter quelques modifications à
`DnsRecord`.

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
    NS {
        domain: String,
        host: String,
        ttl: u32,
    }, // 2
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    }, // 5
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    }, // 15
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    }, // 28
}
```

Voici le gros du travail. Nous devons étendre les fonctions d'écriture et de
lecture des enregistrements. En commençant par la lecture, nous la complétons
avec du code supplémentaire pour chaque type d'enregistrement. Tout d'abord, il
y a le préambule commun :

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
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    ((raw_addr1 >> 0) & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    ((raw_addr2 >> 0) & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    ((raw_addr3 >> 0) & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    ((raw_addr4 >> 0) & 0xFFFF) as u16,
                );

                Ok(DnsRecord::AAAA {
                    domain: domain,
                    addr: addr,
                    ttl: ttl,
                })
            }
            QueryType::NS => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;

                Ok(DnsRecord::NS {
                    domain: domain,
                    host: ns,
                    ttl: ttl,
                })
            }
            QueryType::CNAME => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;

                Ok(DnsRecord::CNAME {
                    domain: domain,
                    host: cname,
                    ttl: ttl,
                })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut mx = String::new();
                buffer.read_qname(&mut mx)?;

                Ok(DnsRecord::MX {
                    domain: domain,
                    priority: priority,
                    host: mx,
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

    - snip -
}
```

C'est un peu indigeste, mais aucun enregistrement n'est particulièrement
compliqué en lui-même : c'est de les voir tous ensemble qui donne cette
impression de lourdeur.

### Étendre BytePacketBuffer pour modifier des valeurs sur place

Avant de passer à l'écriture des enregistrements, nous devons ajouter deux
fonctions supplémentaires à `BytePacketBuffer` :

```rust
impl BytePacketBuffer {

    - snip -

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buf[pos] = val;

        Ok(())
    }

    fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }

}
```

Lorsque nous écrivons les labels d'un enregistrement, nous ne connaissons pas
à l'avance le nombre d'octets nécessaires, puisque nous pourrions utiliser des
sauts pour réduire la taille. Nous résolvons ce problème en écrivant d'abord
une taille nulle, puis en revenant en arrière pour y inscrire la taille réelle.

### Étendre DnsRecord pour écrire les nouveaux types d'enregistrements

Nous pouvons maintenant compléter `DnsRecord::write`. Voici notre nouvelle
fonction :

```rust
impl DnsRecord {

    - snip -

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}
```

Encore une bonne quantité de code supplémentaire, mais c'est heureusement la
dernière chose à faire. Nous n'utilisons toujours pas la partie écriture, mais
elle nous sera utile lorsque nous écrirons notre serveur.

### Tester les nouveaux types d'enregistrements

Nous sommes prêts à relancer notre requête pour *www.yahoo.com* :

```text
DnsHeader {
    id: 6666,
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
    answers: 3,
    authoritative_entries: 0,
    resource_entries: 0
}
DnsQuestion {
    name: "www.yahoo.com",
    qtype: A
}
CNAME {
    domain: "www.yahoo.com",
    host: "fd-fp3.wg1.b.yahoo.com",
    ttl: 3
}
A {
    domain: "fd-fp3.wg1.b.yahoo.com",
    addr: 46.228.47.115,
    ttl: 19
}
A {
    domain: "fd-fp3.wg1.b.yahoo.com",
    addr: 46.228.47.114,
    ttl: 19
}
```

Pour faire bonne mesure, essayons aussi une requête MX :

```rust
let qname = "yahoo.com";
let qtype = QueryType::MX;
```

Ce qui donne :

```text
- snip -
DnsQuestion {
    name: "yahoo.com",
    qtype: MX
}
MX {
    domain: "yahoo.com",
    priority: 1,
    host: "mta6.am0.yahoodns.net",
    ttl: 1794
}
MX {
    domain: "yahoo.com",
    priority: 1,
    host: "mta7.am0.yahoodns.net",
    ttl: 1794
}
MX {
    domain: "yahoo.com",
    priority: 1,
    host: "mta5.am0.yahoodns.net",
    ttl: 1794
}
```

Prochaine étape : [Chapitre 4 - Notre tout premier serveur DNS](chapter4.md)
