Construire un serveur DNS en Rust
=================================

> 🌐 **Français** · [Other languages](../../README.md#languages)

*Traduction de la [version anglaise](../en/README.md) (révision `029d450`).*

Internet repose sur des fondations conceptuelles riches, faites de nombreuses
idées passionnantes qui lui permettent de fonctionner tel que nous le
connaissons. L'une des plus réussies est DNS. Avant son invention, tout le
monde sur Internet (et il faut reconnaître qu'il n'y avait pas grand monde à
l'époque) s'appuyait sur un fichier partagé appelé HOSTS.TXT, maintenu par le
Stanford Research Institute. Ce fichier était synchronisé à la main via FTP, et
à mesure que le nombre d'hôtes augmentait, la fréquence des modifications
augmentait elle aussi, rendant le système de moins en moins tenable. En 1983,
Paul Mockapetris s'est attelé à trouver une solution durable au problème, et a
fini par concevoir et implémenter DNS. Que sa création ait pu passer de
quelques milliers d'ordinateurs à l'Internet que nous connaissons aujourd'hui
témoigne de son génie.

Avec le double objectif de comprendre DNS en profondeur et de faire quelque
chose d'intéressant en Rust, mais aussi pour satisfaire ma propre curiosité,
je me suis lancé dans l'implémentation de mon propre serveur DNS. Ce document
n'est pas une chronique fidèle de ce parcours, mais plutôt une version
idéalisée, débarrassée de tous les détours que j'ai fini par prendre. Nous
allons implémenter progressivement un serveur DNS complet, en partant des
principes de base.

 * [Chapitre 1 - Le protocole DNS](chapter1.md)
 * [Chapitre 2 - Construire un résolveur de souche](chapter2.md)
 * [Chapitre 3 - Ajouter d'autres types d'enregistrements](chapter3.md)
 * [Chapitre 4 - Notre tout premier serveur DNS](chapter4.md)
 * [Chapitre 5 - Résolution récursive](chapter5.md)

Exemples
--------

Chaque chapitre est accompagné d'un exemple contenant le code complet
jusqu'à ce point du guide, nommés `sample1.rs` à `sample5.rs` et situés dans
le répertoire [`examples/`](../../examples/). On peut les exécuter depuis la
racine du dépôt, par exemple pour le premier chapitre avec
`cargo run --example sample1`.

Les commentaires du code ont été traduits dans les chapitres, mais les
fichiers d'exemple, communs à toutes les langues, restent commentés en
anglais.

Voir l'[historique des révisions](../../README.md#revision-history).
