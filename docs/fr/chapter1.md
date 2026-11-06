1 - Le protocole DNS
====================

Nous allons commencer par étudier le protocole DNS, puis utiliser ce que nous
en aurons appris pour implémenter un client simple.

Par convention, les paquets DNS sont transportés par UDP et limités à 512
octets. Comme nous le verrons plus tard, ces deux règles ont des exceptions :
DNS peut aussi fonctionner sur TCP, et un mécanisme appelé eDNS permet
d'augmenter la taille des paquets. Pour l'instant, nous nous en tiendrons
toutefois à la spécification d'origine.

DNS a l'avantage d'utiliser le même format pour les requêtes et les réponses.
Cela signifie qu'une fois que nous aurons écrit un analyseur (*parser*) et un
générateur de paquets, notre travail sur le protocole sera terminé. C'est une
différence avec la plupart des protocoles Internet, qui utilisent généralement
des structures différentes pour les requêtes et les réponses. Vu de haut, un
paquet DNS se présente ainsi :

| Section                                  | Taille    | Type                     | Rôle                                                                                                              |
| ---------------------------------------- | --------- | ------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| En-tête (*Header*)                       | 12 octets | Header                   | Informations sur la requête ou la réponse.                                                                        |
| Section Question (*Question Section*)    | Variable  | Liste de questions       | En pratique, une seule question indiquant le nom recherché (le domaine) et le type d'enregistrement souhaité.      |
| Section Réponse (*Answer Section*)       | Variable  | Liste d'enregistrements  | Les enregistrements pertinents du type demandé.                                                                   |
| Section Autorité (*Authority Section*)   | Variable  | Liste d'enregistrements  | Une liste de serveurs de noms (enregistrements NS), utilisée pour résoudre les requêtes de manière récursive.       |
| Section Additionnelle (*Additional Section*) | Variable | Liste d'enregistrements | Des enregistrements supplémentaires qui peuvent être utiles, par exemple les enregistrements A correspondant aux enregistrements NS. |

Nous devons donc essentiellement prendre en charge trois objets différents :
l'en-tête, la question et l'enregistrement (*record*). Fort heureusement, les
listes d'enregistrements et de questions sont simplement des instances
individuelles placées les unes à la suite des autres, sans rien d'autre. Le
nombre d'enregistrements de chaque section est fourni par l'en-tête, dont la
structure est la suivante :

| Nom RFC  | Nom descriptif                              | Longueur | Description                                                                                                                                                                                       |
| -------- | ------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID       | Identifiant du paquet (*Packet Identifier*) | 16 bits  | Un identifiant aléatoire est attribué aux paquets de requête. Les paquets de réponse doivent reprendre le même identifiant. C'est nécessaire pour distinguer les réponses, UDP étant sans état.  |
| QR       | Requête/Réponse (*Query Response*)          | 1 bit    | 0 pour les requêtes, 1 pour les réponses.                                                                                                                                                         |
| OPCODE   | Code d'opération (*Operation Code*)         | 4 bits   | Presque toujours 0, voir la RFC1035 pour les détails.                                                                                                                                             |
| AA       | Réponse faisant autorité (*Authoritative Answer*) | 1 bit | Vaut 1 si le serveur qui répond fait autorité sur le domaine demandé, c'est-à-dire qu'il en est « propriétaire ».                                                                              |
| TC       | Message tronqué (*Truncated Message*)       | 1 bit    | Vaut 1 si la longueur du message dépasse 512 octets. Traditionnellement, c'est une indication que la requête peut être renvoyée en TCP, qui n'est pas soumis à cette limite.                     |
| RD       | Récursion souhaitée (*Recursion Desired*)   | 1 bit    | Positionné par l'émetteur de la requête si le serveur doit tenter de résoudre la requête récursivement lorsqu'il ne dispose pas directement de la réponse.                                         |
| RA       | Récursion disponible (*Recursion Available*) | 1 bit   | Positionné par le serveur pour indiquer s'il accepte ou non les requêtes récursives.                                                                                                              |
| Z        | Réservé (*Reserved*)                        | 3 bits   | Réservé à l'origine pour un usage futur, mais désormais utilisé pour les requêtes DNSSEC.                                                                                                         |
| RCODE    | Code de réponse (*Response Code*)           | 4 bits   | Positionné par le serveur pour indiquer le statut de la réponse, c'est-à-dire si elle a réussi ou échoué, et dans ce dernier cas pour donner des détails sur la cause de l'échec.                  |
| QDCOUNT  | Nombre de questions (*Question Count*)      | 16 bits  | Le nombre d'entrées dans la section Question.                                                                                                                                                     |
| ANCOUNT  | Nombre de réponses (*Answer Count*)         | 16 bits  | Le nombre d'entrées dans la section Réponse.                                                                                                                                                      |
| NSCOUNT  | Nombre d'autorités (*Authority Count*)      | 16 bits  | Le nombre d'entrées dans la section Autorité.                                                                                                                                                     |
| ARCOUNT  | Nombre d'additionnels (*Additional Count*)  | 16 bits  | Le nombre d'entrées dans la section Additionnelle.                                                                                                                                                |

La question est nettement moins effrayante :

| Champ          | Type                | Description                                                                     |
| -------------- | ------------------- | ------------------------------------------------------------------------------- |
| Nom (*Name*)   | Suite de labels     | Le nom de domaine, encodé sous forme de suite de labels, comme décrit plus bas. |
| Type           | Entier sur 2 octets | Le type d'enregistrement.                                                       |
| Classe (*Class*) | Entier sur 2 octets | La classe, en pratique toujours égale à 1.                                    |

La difficulté réside dans l'encodage du nom de domaine, sur lequel nous
reviendrons plus tard.

Enfin, il y a les enregistrements, qui constituent le cœur du protocole. Il
existe de nombreux types d'enregistrements, mais pour l'instant nous ne nous
intéresserons qu'à quelques-uns, essentiels. Tous les enregistrements
commencent par le préambule suivant :

| Champ            | Type                | Description                                                                                       |
| ---------------- | ------------------- | ------------------------------------------------------------------------------------------------- |
| Nom (*Name*)     | Suite de labels     | Le nom de domaine, encodé sous forme de suite de labels, comme décrit plus bas.                   |
| Type             | Entier sur 2 octets | Le type d'enregistrement.                                                                         |
| Classe (*Class*) | Entier sur 2 octets | La classe, en pratique toujours égale à 1.                                                        |
| TTL              | Entier sur 4 octets | Durée de vie (*Time-To-Live*), c'est-à-dire combien de temps un enregistrement peut être mis en cache avant de devoir être redemandé. |
| Len              | Entier sur 2 octets | Longueur des données propres au type d'enregistrement.                                            |

Nous sommes maintenant prêts à examiner des types d'enregistrements précis, en
commençant par le plus essentiel : l'enregistrement A, qui associe un nom à une
adresse IP.

| Champ                    | Type                        | Description                                                                 |
| ------------------------ | --------------------------- | --------------------------------------------------------------------------- |
| Préambule (*Preamble*)   | Préambule d'enregistrement  | Le préambule décrit ci-dessus, avec le champ de longueur égal à 4.          |
| IP                       | Entier sur 4 octets         | Une adresse IP encodée sous forme d'entier sur quatre octets.               |

Arrivés à ce stade, voyons concrètement ce que cela donne en effectuant une
résolution avec l'outil `dig` :

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

Nous utilisons l'option `+noedns` pour être sûrs de rester sur le format
d'origine. Quelques points sont à noter dans la sortie ci-dessus :

 * On voit que `dig` décrit explicitement l'en-tête, la section Question et la
   section Réponse du paquet de réponse.
 * L'en-tête utilise l'OPCODE QUERY, qui correspond à 0. Le statut (RESCODE)
   vaut NOERROR, soit 0 en valeur numérique. L'identifiant est 36383 et changera
   aléatoirement d'une requête à l'autre. Les drapeaux Query Response (qr),
   Recursion Desired (rd) et Recursion Available (ra) sont activés, c'est-à-dire
   qu'ils valent 1. Nous pouvons ignorer `ad` pour l'instant, car il concerne
   DNSSEC. Enfin, l'en-tête nous indique qu'il y a une question et un
   enregistrement de réponse.
 * La section Question affiche notre question : `IN` indique la classe, et A
   nous dit que nous demandons des enregistrements A.
 * La section Réponse contient l'enregistrement de réponse avec l'IP de Google.
   `204` est le TTL, IN est à nouveau la classe et A le type d'enregistrement.
   Vient enfin l'adresse IP de google.com.
 * La dernière ligne nous indique que la taille totale du paquet était de 44
   octets.

Certains détails restent toutefois cachés ici ; allons donc plus loin et
examinons un dump hexadécimal (*hexdump*) des paquets. Nous pouvons utiliser
`netcat` pour écouter sur un port, puis demander à `dig` d'y envoyer la
requête. Dans une première fenêtre de terminal, lancez :

```text
# nc -u -l 1053 > query_packet.txt
```

Puis, dans une autre fenêtre :

```text
# dig +retry=0 -p 1053 @127.0.0.1 +noedns google.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +retry=0 -p 1053 @127.0.0.1 +noedns google.com
; (1 server found)
;; global options: +cmd
;; connection timed out; no servers could be reached
```

L'échec est attendu ici, puisque `dig` abandonne au bout d'un délai lorsqu'il
ne reçoit pas de réponse. Comme la commande échoue, elle se termine. On peut
alors quitter `netcat` avec Ctrl+C. Il nous reste un paquet de requête dans
`query_packet.txt`. Nous pouvons nous en servir pour enregistrer également un
paquet de réponse :

```text
# nc -u 8.8.8.8 53 < query_packet.txt > response_packet.txt
```

Attendez une seconde, puis interrompez avec Ctrl+C. Nous sommes maintenant
prêts à inspecter nos paquets :

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

Essayons d'y voir clair. Nous savons que l'en-tête fait 12 octets. Pour le
paquet de requête, les octets de l'en-tête sont :
`86 2a 01 20 00 01 00 00 00 00 00 00`. On constate que les huit derniers
octets correspondent aux longueurs des différentes sections, et que la seule
ayant un contenu est la section Question, qui contient une seule entrée. La
partie la plus intéressante, ce sont les quatre premiers octets, qui
correspondent aux différents champs de l'en-tête. Tout d'abord, nous savons
qu'il y a un identifiant sur 2 octets, censé être identique dans la requête et
la réponse. On voit effectivement que dans cet exemple il vaut `86 2a` dans les
deux dumps. Les deux octets restants sont plus difficiles à décoder. Pour les
comprendre, il faut les convertir en binaire. En commençant par le `01 20` du
paquet de requête, on obtient (bit de poids fort en premier) :

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

À l'exception du bit lié à DNSSEC dans la partie `Z`, c'est conforme à nos
attentes. `QR` vaut 0 puisqu'il s'agit d'une requête, `OPCODE` vaut aussi 0
puisqu'il s'agit d'une résolution standard, les drapeaux `AA`, `TC` et `RA` ne
sont pas pertinents pour les requêtes, tandis que `RD` est positionné, car
`dig` demande par défaut une résolution récursive. Enfin, `RCODE` n'est pas
non plus utilisé dans les requêtes.

Passons aux octets de drapeaux du paquet de réponse, `81 80` :

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

Comme il s'agit d'une réponse, `QR` est positionné, tout comme `RA`, qui
indique que le serveur prend en charge la récursion. En regardant les huit
octets restants de la réponse, on voit qu'en plus d'une question unique, nous
avons aussi un unique enregistrement de réponse.

Juste après l'en-tête vient la question. Décortiquons-la octet par octet :

```text
                    query name              type   class
       -----------------------------------  -----  -----
HEX    06 67 6f 6f 67 6c 65 03 63 6f 6d 00  00 01  00 01
ASCII     g  o  o  g  l  e     c  o  m
DEC    6                    3           0       1      1
```

Comme indiqué dans le tableau précédent, elle se compose de trois parties : le
nom recherché, le type et la classe. La manière dont le nom est encodé est
cependant intéressante : il n'y a aucun point. DNS encode en fait chaque nom
sous la forme d'une suite de `labels`, chacun précédé d'un octet indiquant sa
longueur. Dans l'exemple ci-dessus, « google » fait 6 octets et est donc
précédé de `0x06`, tandis que « com » fait 3 octets et est précédé de `0x03`.
Enfin, tous les noms se terminent par un label de longueur nulle, c'est-à-dire
un octet nul. Plutôt simple, non ? Eh bien, comme nous allons bientôt le voir,
il y a une subtilité supplémentaire.

Nous avons atteint la fin du paquet de requête, mais il reste des données à
décoder dans le paquet de réponse. Il s'agit d'un unique enregistrement A
contenant l'adresse IP correspondant à google.com :

```text
      name     type   class         ttl        len      ip
      ------  ------  ------  --------------  ------  --------------
HEX   c0  0c  00  01  00  01  00  00  01  25  00  04  d8  3a  d3  8e
DEC   192 12    1       1           293         4     216 58  211 142
```

L'essentiel est conforme à nos attentes : le type vaut 1 pour un
`enregistrement A`, la classe vaut 1 pour `IN`, le TTL est ici de 293, ce qui
semble raisonnable, la longueur des données est de 4, comme il se doit, et nous
apprenons enfin que l'IP de Google est `216.58.211.142`. Mais alors, que se
passe-t-il avec le champ du nom ? Où sont passés les labels que nous venons de
découvrir ?

En raison de la contrainte de taille d'origine de DNS, 512 octets par paquet,
une forme de compression était nécessaire. Comme l'essentiel de l'espace est
occupé par les noms de domaine, et que des morceaux d'un même nom ont tendance à
se répéter, il y a une économie de place évidente à réaliser. Prenons par
exemple la requête DNS suivante :

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

Ici, nous interrogeons l'un des serveurs racine d'Internet pour connaître les
serveurs de noms qui gèrent le domaine de premier niveau (*TLD*) .com.
Remarquez comme `gtld-servers.net.` revient sans cesse : ne serait-il pas
pratique de ne l'inclure qu'une seule fois ? Une façon d'y parvenir consiste à
insérer une « instruction de saut » (*jump directive*) qui indique à
l'analyseur de sauter à une autre position et d'y terminer la lecture du nom.
Il se trouve que c'est exactement ce que nous observons dans notre paquet de
réponse.

J'ai mentionné plus haut que chaque label est précédé d'un octet de longueur.
Ce qu'il faut ajouter, c'est que si les deux bits de poids fort (*MSB*) de cet
octet de longueur sont positionnés, celui-ci est en fait suivi d'un second
octet. Ces deux octets pris ensemble, une fois les deux bits de poids fort
retirés, indiquent la position du saut. Dans l'exemple ci-dessus, nous avons
`0xC00C`. Le motif des deux bits de poids fort exprimé en hexadécimal est
`0xC000` (en binaire `11000000 00000000`) ; on obtient donc la position du saut
en appliquant un XOR entre nos deux octets et ce masque pour les mettre à zéro :
`0xC00C ^ 0xC000 = 12`. Il faut donc sauter à l'octet 12 du paquet et lire à
partir de là. En se rappelant que l'en-tête DNS fait justement 12 octets, on
comprend qu'on nous demande de lire à partir du début de la partie question du
paquet, ce qui est logique puisque la question commence par le domaine
recherché, ici « google.com ». Une fois le nom lu, on reprend l'analyse là où
on s'était arrêté et on passe au type d'enregistrement.

### BytePacketBuffer

Nous en savons enfin assez pour commencer à implémenter ! La première chose
dont nous avons besoin, c'est d'un moyen pratique de manipuler les paquets.
Pour cela, nous allons utiliser une `struct` appelée `BytePacketBuffer`.

```rust
pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {

    /// Fournit un tampon vierge pour stocker le contenu du paquet, ainsi
    /// qu'un champ pour savoir où nous en sommes.
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    /// Position courante dans le tampon
    fn pos(&self) -> usize {
        self.pos
    }

    /// Avance la position dans le tampon d'un nombre de pas donné
    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }

    /// Change la position dans le tampon
    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    /// Lit un octet et avance la position d'un pas
    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Récupère un octet sans modifier la position dans le tampon
    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err("End of buffer".into());
        }
        Ok(self.buf[pos])
    }

    /// Récupère une plage d'octets
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err("End of buffer".into());
        }
        Ok(&self.buf[start..start + len as usize])
    }

    /// Lit deux octets et avance de deux pas
    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    /// Lit quatre octets et avance de quatre pas
    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }


    /// Lit un qname
    ///
    /// La partie délicate : lire les noms de domaine en tenant compte des
    /// labels. Prend quelque chose comme [3]www[6]google[3]com[0] et ajoute
    /// www.google.com à outstr.
    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        // Comme nous pouvons rencontrer des sauts, nous suivons notre position
        // localement au lieu d'utiliser celle de la struct. Cela nous permet
        // de placer la position partagée juste après le qname courant, tout
        // en suivant notre progression sur ce qname grâce à cette variable.
        let mut pos = self.pos();

        // indique si nous avons effectué un saut ou non
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        // Le séparateur que nous ajoutons pour chaque label. Comme nous ne
        // voulons pas de point au début du nom de domaine, nous le laissons
        // vide pour l'instant et le passons à "." à la fin de la première
        // itération.
        let mut delim = "";
        loop {
            // Les paquets DNS sont des données non fiables, il faut donc être
            // paranoïaque. Quelqu'un peut forger un paquet contenant un cycle
            // dans les instructions de saut. Ceci protège contre ce genre de
            // paquets.
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            // À ce stade, nous sommes toujours au début d'un label. Pour
            // rappel, les labels commencent par un octet de longueur.
            let len = self.get(pos)?;

            // Si les deux bits de poids fort de len sont positionnés, il
            // s'agit d'un saut vers une autre position dans le paquet :
            if (len & 0xC0) == 0xC0 {
                // Place la position du tampon juste après le label courant.
                // Nous n'avons plus besoin d'y toucher ensuite.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Lit un octet supplémentaire, calcule le décalage et effectue
                // le saut en mettant à jour notre variable de position locale
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indique qu'un saut a été effectué.
                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // Le cas de base, où nous lisons un label et l'ajoutons à la
            // sortie :
            else {
                // Avance d'un octet pour passer l'octet de longueur.
                pos += 1;

                // Les noms de domaine se terminent par un label vide de
                // longueur 0 : si la longueur est nulle, nous avons fini.
                if len == 0 {
                    break;
                }

                // Ajoute d'abord le séparateur au tampon de sortie.
                outstr.push_str(delim);

                // Extrait les octets ASCII de ce label et les ajoute au
                // tampon de sortie.
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Avance de toute la longueur du label.
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

Avant de passer à l'en-tête, ajoutons une enum pour les valeurs du champ
`rescode` :

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

Nous pouvons maintenant nous attaquer à l'en-tête. Nous le représenterons
ainsi :

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

L'implémentation demande beaucoup de manipulations de bits :

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

Avant de passer à la partie question du paquet, il nous faut un moyen de
représenter le type d'enregistrement demandé :

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

L'enum nous permettra d'ajouter facilement d'autres types d'enregistrements
par la suite. Passons maintenant aux entrées de la section Question :

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
        let _ = buffer.read_u16()?; // classe

        Ok(())
    }
}
```

Comme la partie difficile, la lecture des noms de domaine, est déjà prise en
charge par notre struct `BytePacketBuffer`, ce code s'avère plutôt compact.

### DnsRecord

Il nous faut évidemment aussi un moyen de représenter les enregistrements DNS
eux-mêmes, et nous utiliserons là encore une enum pour pouvoir l'étendre
facilement :

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

Comme il existe de nombreux types d'enregistrements, nous ajoutons la
possibilité de conserver la trace des types que nous ne connaissons pas
encore. L'enum nous permettra aussi d'ajouter facilement de nouveaux
enregistrements plus tard. L'implémentation de `DnsRecord` ressemble à ceci :

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

Enfin, assemblons le tout dans une struct appelée `DnsPacket` :

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

### Assemblage final

Utilisons le fichier `response_packet.txt` généré plus tôt pour essayer tout
cela !

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

L'exécution affiche :

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

Dans le prochain chapitre, nous ajouterons la connectivité réseau :
[Chapitre 2 - Construire un résolveur de souche](chapter2.md)
