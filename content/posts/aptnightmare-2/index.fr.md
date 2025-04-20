---
title: APTNightmare-2
description: 🔎 Linux Memory Forensic 
slug: aptnightmare2
date: 2025-04-21 00:00:05+0000
tags: ["HackTheBox", "Sherlock", "Hard", "Linux"]
---

![](pictures/lab.png)

## Scénario
> À l'issue du processus de récupération du serveur, l'équipe IR a découvert un labyrinthe de trafic persistant, de communications subreptices et de processus résistants qui ont échappé à nos efforts d'arrêt. Il est évident que la portée de l'incident dépasse la violation initiale de nos serveurs et de nos clients. En tant qu'expert en forensic, pouvez-vous éclairer les ombres qui cachent ces activités clandestines ?


## Setup
Pour ce Sherlock nous allons utiliser : 
- Volatility2
- IDA

Pour nous aider on va aussi s'appuyer sur cette cheatsheet tels que :
- https://downloads.volatilityfoundation.org/releases/2.4/CheatSheet_v2.4.pdf

### Profil volatility
Premièrement on doit installer python2, volatility2 et ajouter le profil nécessaire.

Un profil Volatility est un fichier contenant des informations structurelles sur le système d'exploitation cible. Pour simplifier, c'est comme une "carte" qui permet à Volatility de comprendre comment les données sont organisées dans la mémoire d'un système spécifique.

Ce profil contient principalement deux types d'informations :
- les définitions des structures de données du kernel
- les symboles du kernel (adresses des fonctions et variables)

Installation :
```bash
sudo apt install -y python2 python2-dev build-essential libdistorm3-dev libssl-dev libffi-dev zlib1g-dev

curl -sS https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py

sudo python2 get-pip.py

sudo python2 -m pip install --upgrade pip setuptools wheel

sudo python2 -m pip install distorm3 pycrypto openpyxl pillow yara-python

git clone https://github.com/volatilityfoundation/volatility.git

cd volatility

python2 vol.py -h
```

![](pictures/vol2.png)

Profil :
```bash
cp Ubuntu_5.3.0-70-generic_profile.zip /home/kali/Documents/volatility/volatility/plugins/overlays/linux/

python2 vol.py --info | grep Linux
```

![](pictures/vol2profil.png)


## Question 1
> Quels sont les IP et le port utilisés par l'attaquant pour le reverse shell ?

Pour cela on va utiliser le module **linux_netstat** de volatility qui permet d'extraire et afficher toutes les connexions réseaux qui étaient présentes lors de la capture mémoire. On va rediriger l'output dans un fichier pour faciliter la recherche via un éditeur de texte / IDE etc.

```bash
python2 vol.py -f ~/Downloads/APTNightmare-2/dump.mem --profile=LinuxUbuntu_5_3_0-70-generic_profilex64 linux_netstat > netstat.txt
```

On est sous Linux, le plus probable c'est de voir un reverse shell bash bien crade, et bingo : 

![netstat](pictures/netstat.png)

**Réponse** : ``10.0.2.6:443``


## Question 2
> Quel était le PPID de la connexion malveillante du reverse shell ?

Premièrement on va tester un ``linux_pstree` : 

```bash
python2 vol.py -f ~/Downloads/APTNightmare-2/dump.mem --profile=LinuxUbuntu_5_3_0-70-generic_profilex64 linux_pstree | grep -C 5 3633
```

![pstree](pictures/pstree.png)

Pas de PPID. Pourquoi ? Le plugin ``linux_pstree`` reconstruit l'arborescence des processus en se basant principalement sur une seule source d'information : la liste des tâches actives du système (``task_struct``).

![kernel map](pictures/kernel-map.png)
https://makelinux.github.io/kernel/map/

On va donc plutôt utiliser le plugin ``linux_psxview`` qui est conçu spécifiquement pour détecter les processus cachés. Il utilise plusieurs sources pour idenfifier les processus : 
- **task_struct list** : la même liste de tâches utilisée par linux_pstree
- **pid hash table** : une structure de hachage utilisée par le kernel pour rechercher rapidement les processus par PID
- **pslist** : liste des processus extraite d'autres sources mémoire
- **kmem_cache** : cache du kernel qui peut contenir des références aux processus
- **d_path** : informations sur les processus tirées du système de fichiers procfs
- **thread_info** : informations des threads qui peuvent révéler des processus cachés

Il compare ensuite les résultats de ces différentes sources et signale les incohérences, par exemple lorsqu'un processus apparaît dans une source mais pas dans une autre.

```bash
python2 vol.py -f ~/Downloads/APTNightmare-2/dump.mem --profile=LinuxUbuntu_5_3_0-70-generic_profilex64 linux_psxview > psxview.txt
```

![psxview](pictures/psxview.png)

Et logiquement, on se doute bien que le parent est le PID juste avant.

Mais pourquoi le cacher ? Au vu du scénario, on sait que l'on a à faire à un rootkit. Ce qui s'est probablement passé c'est que le rootkit a modifié la liste des tâches (*task_struct list*) en "déconnectant" son processus de reverse shell de cette liste chaînée. Concrètement, il a manipulé les pointeurs ``next`` et ``prev`` de cette liste pour que son processus soit ignoré lors du parcours de la liste.

Cependant, le rootkit n'a pas réussi à effacer toutes les traces de son existence. Il a omis de modifier une ou plusieurs des autres structures surveillées par ``linux_psxview``.

Le résultat est que ``linux_pstree``, qui ne se fie qu'à la liste des tâches, ne voit pas le processus malveillant, tandis que ``linux_psxview``, qui vérifie plusieurs sources, le détecte via les structures que le rootkit a négligé de modifier.

**Réponse** : ``3632``


## Question 3
> Indiquer le nom du module malveillant du kernel.

Pour cela on va utiliser le plugin ``linux_check_modules``. Mais avant, remettons en contexte qu'est-ce qu'un module kernel et quel est le lien avec un rootkit.

Un module kernel c'est un morceau de code qui peut être chargé et déchargé dynamiquement dans le kernel d'un système d'exploitation en cours d'exécution. Celma permet d'étendre ses fonctionnalités (comme la prise en charge de nouveaux périphériques ou systèmes de fichiers) sans nécessiter de redémarrer ou de recompiler complétementl le kernel.

Les rootkits opèrent au niveau du kernel Linux en insérant leurs propres modules kernel (LKM - Loadable Kernel Modules). Ces modules malveillants peuvent:
- intercepter les appels système pour dissimuler des fichiers, processus ou connexions
- établir des backdoors persistantes dans le système
- désactiver certaines fonctionnalités de sécurité du kernel
- masquer leur propre présence aux outils standard du système
etc.

Concernant le plugin volatility ``linux_check_modules``. Il est conçu pour détecter les LKM caché en comparant encore une fois différente sources d'information du kernel. 

**1. Analyse de la liste officielle des modules**

Tout d'abord, le plugin examine la liste des modules officiellement chargés (``modules.list``). Cette liste circulairement chaînée est maintenue par le kernel et contient tous les modules légitimement chargés. Elle est accessible via la commande ``lsmod``.

**2. Analyse des symboles du kernel**

Ensuite, il parcourt la table des symboles du kernel (accessible via ``/proc/kallsyms``). Cette table contient les adresses de toutes les fonctions et variables du kernel, y compris celles introduites par des modules chargés.

**3. Analyse de la section modulaire .ko**

Le plugin examine également les sections mémoire où les modules kernel (**.ko**) sont typiquement chargés, recherchant les signatures caractéristiques des modules même s'ils ne sont pas référencés ailleurs.

**4. Techniques de détection des modules cachés**
- la technique principale consiste à comparer les modules trouvés dans la liste officielle avec ceux détectés par l'analyse des symboles ou des sections mémoire. Un module présent dans une source mais absent de la liste officielle est probablement caché intentionnellement.
- le plugin examine également la table des appels système (syscall table) pour détecter si des fonctions originales ont été remplacées par des versions modifiées - une technique courante des rootkits pour intercepter les interactions avec le kernel.
- il vérifie si les adresses des fonctions de modules pointent vers des régions mémoire suspectes ou non standard, ce qui pourrait indiquer du code injecté.
- les attributs des modules sont analysés (comme l'horodatage, le nom, l'auteur) pour détecter des informations incohérentes ou inhabituelles.

> Ok c'est cool mais comment les rootkit se cache au fait ?

Il y a beaucoup de technique différente mais on retrouve généralement : 
- **DKOM (Direct Kernel Object Manipulation)** : 
Ils modifient les structures de données du kernel en mémoire pour retirer leur module de la liste modules.list, tout en laissant le module fonctionnel.

- **Hooks de syscall** :
Ils remplacent les fonctions légitimes du kernel par leurs propres versions qui filtrent les résultats (par exemple, une version modifiée de read qui ne montre jamais certains fichiers).

- **Module sans nom** :
Certains modules malveillants utilisent des chaînes vides ou des caractères spéciaux comme nom pour compliquer leur détection.

Enfin bref, revenons à la question. 

```bash
python2 vol.py -f ~/Downloads/APTNightmare-2/dump.mem --profile=LinuxUbuntu_5_3_0-70-generic_profilex64 linux_check_modules 
```

![linux_check_modules](pictures/modules.png)

Le nom **"nfentlink"** est une tentative de camouflage d'un module malveillant en se faisant passer pour **"nfnetlink"**, qui est un module kernel légitime de Linux utilisé pour la communication entre l'espace kernel et l'espace utilisateur pour le firewall et le réseau.

**Réponse** : ``nfentlink``


## Question 4
> Quand est-ce que le module a été chargé ?

Premièrement j'étais partie sur une mauvaise piste. Ma pensée était : 
- prendre le timestamp du chargement du module dans dmesg via ``linux_dmesg``
- prendre le timestamp du boot dans ``linux_pslist``
- calculer et hop 

Cela aurait fonctionné si c'était la première fois que le module était chargé. Néanmoins, il a déjà été chargé dans le passé. Ma méthode est vraiment mauvaise par défaut, en cas de réponse à incident cela peut vous induire en erreur. 

Au final j'ai remis tout à plat et je me suis dit "où puis-je trouver des timestamp lié à des actions passées après de multiple boot ?".

Les logs systèmes évidemment. Tout particulièrement ``/var/log/kern.log`` ou ``/var/log/syslog.log``.

Pour récupérer ces fichiers on va premièrement énumérer les fichiers dans la capture mémoire : 

```bash
python2 vol.py -f ~/Downloads/APTNightmare-2/dump.mem --profile=LinuxUbuntu_5_3_0-70-generic_profilex64 linux_enumerate_files > files.txt
```

Et en effet on retrouve bien :
![enumerate](pictures/enumerate.png)

Ensuite, pour extraire ``/var/log/kern.log`` on va : 

```bash
python2 vol.py -f ~/Downloads/APTNightmare-2/dump.mem --profile=LinuxUbuntu_5_3_0-70-generic_profilex64 linux_find_file -i 0xffff98ea5a732fa8 -O kern.log
```
![kernel.log](pictures/kernel.log.png)

**Réponse** : ``2024-05-01 20:42:57``


## Question 5
> Quel est le chemin d'accès complet et le nom du fichier du module du kernel malveillant ?

Pareil on va check dans les fichiers énumérés. Premièrement on cherche le module qu'on a identifié "nfentlink".

```bash
cat files.txt |grep nfentlink
```

![](pictures/files.png)

ça ne donne rien d'intéressant. 

On va donc chercher le module qui a le vrai nom pour voir : 

![](pictures/files2.png)

On va revenir sur le deuxième fichier plus tard.

**Réponse** : ``/lib/modules/5.3.0-70-generic/kernel/drivers/net/nfnetlink.ko``


## Question 6
> Quel est le hash MD5 du fichier du module malveillant ?

Il suffit d'extraire le fichier et calculer son hash : 
```bash
python2 vol.py -f ~/Downloads/APTNightmare-2/dump.mem --profile=LinuxUbuntu_5_3_0-70-generic_profilex64 linux_find_file -i 0xffff98ea266b5a68 -O nfnetlink.ko

md5sum nfnetlink.ko
```

![](pictures/hash.png)

**Réponse** : ``35bd8e64b021b862a0e650b13e0a57f7``


## Question 7
> Quel est le chemin d'accès complet et le nom du fichier du module du kernel légitime ?

Revenons au screen de la question 5. 

**Réponse** : ``/lib/modules/5.3.0-70-generic/kernel/net/netfilter/nfnetlink.ko``


## Question 8
> Quelle est la différence d'un seul caractère dans la valeur de l'auteur entre le module légitime et le module malveillant ?

Premièrement on va checker le légitime via **modinfo** qui permet d'afficher des informations détaillés sur un module kernel spécifique. 

```bash
modinfo /lib/modules/6.11.2-amd64/kernel/net/netfilter/nfnetlink.ko.xz
```

![](pictures/modinfo1.png)

Ensuite, on check le module kernel qu'on a récupéré dans la capture : 
```bash
modinfo malicious-nfnetlink.ko
```

![](pictures/modinfo2.png)

On voit donc bien qu'il manque un "i".

**Réponse** : ``i``


## Question 9
> Quel est le nom de la fonction d'initialisation du module du kernel malveillant ?

Pour répondre à cette question je vais utiliser **IDA**. C'est vraiment overkill, on peut se limiter à gdb (gef>gdb), radare2 etc.

On va donc regarder les fonctions :
![](pictures/functions.png)

![](pictures/nfnetlink_init.png)

On voit bien que la fonction d'initialisation est ``nfnetlink_init`` mais aussi ``init_module``. C'est encore plus visible avec gef : 

![](pictures/gef.png)

Gef affiche les deux fonctions à la même adresse mémoire. On voit donc une technique délibérée de camouflage des modules kernel rootkit. 

Le module malveillant utilise la fonction standard ``init_module`` (qui est l'entrée **obligatoire** pour tout module kernel Linux) mais a intentionnellement renommé cette fonction en ``nfnetlink_init`` pour ressembler au module légitime du kernel. 

Les symboles d'exportation comme ``init_module`` sont essentiels pour que le kernel Linux puisse charger le module, mais l'attaquant a utilisé des astuces de compilation pour que la même fonction porte deux noms différents, l'un pour le chargement par le kernel et l'autre pour le camouflage visuel.

**Réponse** : ``nfnetlink_init``

## Question 10
> Il existe une fonction pour hooker les syscall. Quel est le dernier syscall du tableau ?

Dans la fonction ``nfnetlink_init`` on voit bien ``_sys_call_table = kallsyms_lookup_name("sys_call_table");`` :

![](pictures/syscalltable.png)

```nasm
_sys_call_table = kallsyms_lookup_name("sys_call_table");
```
Cette ligne utilise la fonction ``kallsym_lookup_name`` pour obtenir l'adresse de la table des syscall ``sys_call_table`` dans la mémoire du kernel.

``sys_call_table`` est un tableau contenant les pointeurs vers les fonctions des syscall utilisés par le kernel. En modifiant cette table, l'attaquant peut rediriger les syscall vers des fonctions malveillantes.

On va donc aller voir le tableau de données dans la section ``.rodata`` (section contenant des chaînes de caractères et des données en lecture seule). 

Ce tableau contient des références à des symboles qui sont utilisées pour diverses manipulations dans le module malicieux. 

```nasm
aX64SysGetdents       db '_x64_sys_getdents64',0
aX64SysGetdents       db '_x64_sys_getdents',0
aX64SysKill           db '_x64_sys_kill',0
```

Ces chaînes sont des références aux symboles des fonctions système que le module va utiliser ou modifier.

Ces fonctions font partie de l'API des syscall du kernel Linux, et dans ce cas, elles sont hookées ou utilisées pour rediriger des appels.

**Réponse** : ``__x64_sys_kill``


## Question 11
> Quel numéro de signal est utilisé pour masquer le PID d'un processus en cours d'exécution lors de l'envoi ?

On va donc aller voir la fonction ``hook_kill`` :

![hook_kill](pictures/hook_kill.png)

Et ce qui saute aux yeux c'est bien : 
```nasm
cmp     dword ptr [rdi+68h], 64
```

ainsi que le ``hide_pid``.

Allons voir le pseudocode généré par IDA : 

![hook_kill](pictures/code_hook_kill.png)

```C
if ( (*(DWORD *)(a1 + 104)) != 64 )
    return ((__int64 (*) (void))orig_kill());
```

- ``a1 + 104`` : cela accède au signal envoyé avec l'appel kill(). Le champ à l'adresse ``a1 + 104`` correspond donc au signal.

- ``(*(DWORD *)(a1 + 104)) != 64`` : cette condition vérifie si le signal n'est pas égal à 64.

Si le signal n'est pas égal à 64, la fonction exécute la fonction ``orig_kill`` (l'originale, avant le hook) pour continuer l'exécution normale du kernel.

Sinon il fait appel à ``hide_pid`` : 
```C
sprintf(hide_pid, "%d", *((QWORD *)(a1 + 112)));
```

- ``sprintf(hide_pid, "%d", ...) ``: la fonction ``sprintf`` est utilisée ici pour formater et passer le PID dans la fonction ``hide_pid``. Cela suggère que le module utilise ce PID pour appeler la fonction ``hide_pid``, qui est probablement utilisée pour cacher le processus du système (par exemple en supprimant les entrées dans /proc, dans les répertoires système, ou d'autres structures de données du kernel).

- ``hide_pid`` : est la fonction pour cacher un processus, empêchant ainsi sa visibilité.

- ``%d`` : C'est un format pour afficher l'entier (le PID).

**Réponse** : ``64``

---

Lab terminé  !

![](pictures/finished.png)
