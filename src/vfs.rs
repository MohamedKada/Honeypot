// ============================================================================
// vfs.rs — Faux système de fichiers en mémoire (Virtual Filesystem)
// ============================================================================
//
// Le VFS est un HashMap<String, VfsEntry> où :
//   - La clé = chemin absolu normalisé  ("/etc/passwd")
//   - La valeur = fichier (contenu) ou répertoire
//
// Tout est chargé en mémoire au démarrage depuis le persona.
// Résultat : aucune latence pendant les sessions, cohérence garantie.
// ============================================================================

use std::collections::HashMap;
use crate::persona::Persona;

// ----------------------------------------------------------------------------
// Types de base
// ----------------------------------------------------------------------------

/// Une entrée dans le VFS : soit un fichier avec son contenu, soit un dossier.
pub enum VfsEntry {
    Fichier(String),   // contenu texte
    Repertoire,
}

/// Le système de fichiers virtuel complet.
pub struct Vfs {
    entrees: HashMap<String, VfsEntry>,
}

impl Vfs {
    // ── Construction ─────────────────────────────────────────────────────────

    /// Construit le VFS complet à partir du persona choisi.
    pub fn construire(persona: &Persona) -> Self {
        let mut vfs = Vfs { entrees: HashMap::new() };

        // Répertoires racines communs à tous les systèmes Linux
        for dir in &["/", "/etc", "/etc/ssh", "/home", "/var", "/var/log",
                     "/var/tmp", "/tmp", "/opt", "/proc", "/usr", "/usr/bin",
                     "/usr/local", "/usr/local/bin", "/root", "/run", "/sys"] {
            vfs.dir(dir);
        }

        // Home de l'utilisateur du persona
        let home = &persona.shell.home;
        vfs.dir(home);
        vfs.dir(&format!("{}/.ssh", home));
        vfs.dir(&format!("{}/.cache", home));
        vfs.dir(&format!("{}/.config", home));

        // Fichiers système communs
        vfs.fichiers_communs(persona);

        // Fichiers spécifiques au persona
        match persona.id.as_str() {
            "web-server"   => vfs.fichiers_web(persona),
            "database"     => vfs.fichiers_database(persona),
            "dev-machine"  => vfs.fichiers_dev(persona),
            _              => vfs.fichiers_web(persona), // fallback
        }

        vfs
    }

    // ── Accès public ─────────────────────────────────────────────────────────

    /// Récupère une entrée par son chemin absolu.
    pub fn get(&self, chemin: &str) -> Option<&VfsEntry> {
        self.entrees.get(&normaliser(chemin))
    }

    /// Vérifie si un chemin existe.
    pub fn existe(&self, chemin: &str) -> bool {
        self.entrees.contains_key(&normaliser(chemin))
    }

    /// Liste le contenu d'un répertoire.
    /// Retourne les paires (nom_court, entrée) triées.
    pub fn lister(&self, chemin: &str) -> Vec<(String, &VfsEntry)> {
        let parent = normaliser(chemin);
        let mut enfants: Vec<(String, &VfsEntry)> = self.entrees
            .iter()
            .filter_map(|(chemin_complet, entree)| {
                // On cherche les entrées dont le parent direct est `parent`
                if let Some(nom) = enfant_direct(&parent, chemin_complet) {
                    Some((nom.to_string(), entree))
                } else {
                    None
                }
            })
            .collect();

        // Tri : dossiers d'abord, puis fichiers, alphabétique
        enfants.sort_by(|(na, ea), (nb, eb)| {
            let ordre_type = matches!(eb, VfsEntry::Repertoire)
                .cmp(&matches!(ea, VfsEntry::Repertoire));
            if ordre_type == std::cmp::Ordering::Equal {
                na.cmp(nb)
            } else {
                ordre_type
            }
        });

        enfants
    }

    /// Résout un chemin (relatif ou absolu) depuis le répertoire courant.
    ///
    /// Exemples :
    ///   résoudre("/home/ubuntu", "..") → "/home"
    ///   résoudre("/etc", "passwd")     → "/etc/passwd"
    ///   résoudre("/tmp", "/root")      → "/root"
    pub fn resoudre(&self, courant: &str, cible: &str) -> String {
        let base = if cible.starts_with('/') {
            cible.to_string()
        } else {
            format!("{}/{}", courant.trim_end_matches('/'), cible)
        };
        normaliser(&base)
    }

    // ── Helpers privés de construction ────────────────────────────────────────

    fn dir(&mut self, chemin: &str) {
        self.entrees.insert(normaliser(chemin), VfsEntry::Repertoire);
    }

    fn fichier(&mut self, chemin: &str, contenu: &str) {
        // S'assurer que le répertoire parent existe
        if let Some(parent) = parent_de(chemin) {
            self.entrees.entry(normaliser(&parent))
                .or_insert(VfsEntry::Repertoire);
        }
        self.entrees.insert(normaliser(chemin), VfsEntry::Fichier(contenu.to_string()));
    }

    // ── Contenu commun à tous les personas ───────────────────────────────────

    fn fichiers_communs(&mut self, p: &Persona) {
        let sys  = &p.systeme;
        let user = &p.shell.utilisateur;
        let home = &p.shell.home;

        // ── Répertoires supplémentaires ───────────────────────────────────────
        for dir in &[
            "/etc/apt", "/etc/apt/sources.list.d", "/etc/cron.d", "/etc/cron.daily",
            "/etc/cron.weekly", "/etc/security", "/etc/fail2ban", "/etc/fail2ban/jail.d",
            "/etc/systemd", "/etc/systemd/system", "/etc/ufw",
            "/var/backups", "/var/cache", "/var/cache/apt",
            "/var/log/journal",
            "/usr/local/sbin",
        ] {
            self.dir(dir);
        }
        self.dir(&format!("{}/.gnupg", home));
        self.dir(&format!("{}/.local", home));
        self.dir(&format!("{}/.local/share", home));

        // /etc/hostname
        self.fichier("/etc/hostname", &sys.hostname);

        // /etc/os-release
        self.fichier("/etc/os-release", &format!(
            "NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"{os}\"\nVERSION_ID=\"22.04\"\nHOME_URL=\"https://www.ubuntu.com/\"\nSUPPORT_URL=\"https://help.ubuntu.com/\"\nBUG_REPORT_URL=\"https://bugs.launchpad.net/ubuntu/\"\nPRIVACY_POLICY_URL=\"https://www.ubuntu.com/legal/terms-and-policies/privacy-policy\"\nUBUNTU_CODENAME=jammy\n",
            os = sys.os_version
        ));

        // /etc/issue et /etc/issue.net
        self.fichier("/etc/issue", &format!("{} \\n \\l\n\n", sys.os_version));
        self.fichier("/etc/issue.net", &format!("{}\n", sys.os_version));

        // /etc/timezone
        self.fichier("/etc/timezone", "Europe/Paris\n");

        // /etc/hosts
        self.fichier("/etc/hosts", &format!(
            "127.0.0.1\tlocalhost\n127.0.1.1\t{host}\n{ip}\t{host}\n\n# The following lines are desirable for IPv6 capable hosts\n::1     localhost ip6-localhost ip6-loopback\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n",
            host = sys.hostname, ip = sys.ip,
        ));

        // /etc/resolv.conf
        self.fichier("/etc/resolv.conf",
            "# Generated by systemd-resolved\nnameserver 8.8.8.8\nnameserver 8.8.4.4\nsearch company.internal\n"
        );

        // /etc/fstab
        self.fichier("/etc/fstab",
            "# /etc/fstab: static file system information.\n# <file system> <mount point>   <type>  <options>       <dump>  <pass>\nUUID=a3b4c5d6-1234-5678-abcd-ef0123456789 /               ext4    errors=remount-ro 0       1\nUUID=b4c5d6e7-2345-6789-bcde-f01234567890 /boot           ext4    defaults        0       2\nUUID=c5d6e7f8-3456-789a-cdef-012345678901 none            swap    sw              0       0\ntmpfs /tmp tmpfs defaults,nosuid,nodev,noexec 0 0\n"
        );

        // /etc/environment
        self.fichier("/etc/environment",
            "PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin\"\nLANG=en_US.UTF-8\nLC_ALL=en_US.UTF-8\n"
        );

        // /etc/profile
        self.fichier("/etc/profile",
            "# /etc/profile: system-wide .profile file for the Bourne shell\nif [ \"${PS1-}\" ]; then\n  if [ \"${BASH-}\" ] && [ \"$BASH\" != \"/bin/sh\" ]; then\n    if [ -f /etc/bash.bashrc ]; then\n      . /etc/bash.bashrc\n    fi\n  fi\nfi\nif [ -d /etc/profile.d ]; then\n  for i in /etc/profile.d/*.sh; do\n    if [ -r $i ]; then\n      . $i\n    fi\n  done\n  unset i\nfi\n"
        );

        // /etc/bash.bashrc
        self.fichier("/etc/bash.bashrc",
            "# System-wide .bashrc file for interactive bash shells.\nif [ -z \"${debian_chroot:-}\" ] && [ -r /etc/debian_chroot ]; then\n    debian_chroot=$(cat /etc/debian_chroot)\nfi\nPS1='${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ '\numask 022\n"
        );

        // /etc/passwd
        self.fichier("/etc/passwd", &format!(
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nsystemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\nsystemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\nsyslog:x:104:110::/home/syslog:/usr/sbin/nologin\nmessagebus:x:105:109::/nonexistent:/usr/sbin/nologin\n_apt:x:106:65534::/nonexistent:/usr/sbin/nologin\ntss:x:107:113:TPM software stack,,,:/var/lib/tpm:/bin/false\nusbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin\nsshd:x:109:65534::/run/sshd:/usr/sbin/nologin\npollinate:x:110:1::/var/cache/pollinate:/bin/false\n{user}:x:1000:1000:{user},,,:/home/{user}:/bin/bash\n",
            user = user,
        ));

        // /etc/group
        self.fichier("/etc/group", &format!(
            "root:x:0:\ndaemon:x:1:\nbin:x:2:\nsys:x:3:\nadm:x:4:syslog,{user}\ntty:x:5:\ndisk:x:6:\nlp:x:7:\nmail:x:8:\nnews:x:9:\nuucp:x:10:\nman:x:12:\nproxy:x:13:\nkmem:x:15:\ndialout:x:20:{user}\nfax:x:21:\nvoice:x:22:\ncdrom:x:24:{user}\nfloppy:x:25:{user}\ntape:x:26:\nsudo:x:27:{user}\naudio:x:29:{user}\ndip:x:30:{user}\nwww-data:x:33:\nbackup:x:34:\noperator:x:37:\nlist:x:38:\nirc:x:39:\nsrc:x:40:\nnetdev:x:102:{user}\nbluetooth:x:111:\nplugged:x:119:{user}\n{user}:x:1000:\n",
            user = user,
        ));

        // /etc/shadow
        self.fichier("/etc/shadow",
            "root:$6$rounds=4096$xB3kP9mN$hashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhash:19500:0:99999:7:::\ndaemon:*:19500:0:99999:7:::\nbin:*:19500:0:99999:7:::\nsys:*:19500:0:99999:7:::\nsync:*:19500:0:99999:7:::\ngames:*:19500:0:99999:7:::\nnobody:*:19500:0:99999:7:::\nsshd:*:19635:0:99999:7:::\nubuntu:$6$rounds=4096$r4nd0ms4lt$hashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhash:19635:0:99999:7:::\n"
        );

        // /etc/sudoers
        self.fichier("/etc/sudoers",
            "# This file MUST be edited with the 'visudo' command as root.\n#\n# Please consider adding local content in /etc/sudoers.d/ instead of\n# directly modifying this file.\n#\n# See the man page for details on how to write a sudoers file.\n#\nDefaults\tenv_reset\nDefaults\tmail_badpass\nDefaults\tsecure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin\"\nDefaults\tuse_pty\n\n# Host alias specification\n\n# User alias specification\n\n# Cmnd alias specification\n\n# User privilege specification\nroot\tALL=(ALL:ALL) ALL\n\n# Allow members of group sudo to execute any command\n%sudo\tALL=(ALL:ALL) ALL\n\n# See sudoers(5) for more information on '@include' directives:\n@includedir /etc/sudoers.d\n"
        );

        // /etc/ssh/sshd_config
        self.fichier("/etc/ssh/sshd_config",
            "# This is the sshd server system-wide configuration file.\n# See sshd_config(5) for more information.\nPort 22\nAddressFamily any\nListenAddress 0.0.0.0\n\nHostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_ecdsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n\nSyslogFacility AUTH\nLogLevel INFO\n\nLoginGraceTime 2m\nPermitRootLogin prohibit-password\nStrictModes yes\nMaxAuthTries 6\nMaxSessions 10\n\nPubkeyAuthentication yes\nAuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2\n\nPasswordAuthentication yes\nPermitEmptyPasswords no\nChallengeResponseAuthentication no\n\nUsePAM yes\nX11Forwarding yes\nPrintMotd no\nAcceptEnv LANG LC_*\nSubsystem sftp /usr/lib/openssh/sftp-server\n"
        );

        // /etc/apt/sources.list
        self.fichier("/etc/apt/sources.list",
            "# Ubuntu 22.04 LTS Jammy Jellyfish\ndeb http://archive.ubuntu.com/ubuntu/ jammy main restricted universe multiverse\ndeb http://archive.ubuntu.com/ubuntu/ jammy-updates main restricted universe multiverse\ndeb http://archive.ubuntu.com/ubuntu/ jammy-backports main restricted universe multiverse\ndeb http://security.ubuntu.com/ubuntu/ jammy-security main restricted universe multiverse\n"
        );

        // /etc/sysctl.conf
        self.fichier("/etc/sysctl.conf",
            "# /etc/sysctl.conf - Configuration file for setting system variables\nnet.ipv4.ip_forward=0\nnet.ipv4.conf.default.rp_filter=1\nnet.ipv4.conf.all.rp_filter=1\nnet.ipv4.tcp_syncookies=1\nnet.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1\nnet.core.somaxconn=65535\nvm.swappiness=10\nfs.file-max=2097152\n"
        );

        // /etc/logrotate.conf
        self.fichier("/etc/logrotate.conf",
            "# see \"man logrotate\" for details\nweekly\nrotate 4\ncreate\ndateext\ninclude /etc/logrotate.d\n\n/var/log/wtmp {\n    missingok\n    monthly\n    create 0664 root utmp\n    minsize 1M\n    rotate 1\n}\n\n/var/log/btmp {\n    missingok\n    monthly\n    create 0660 root utmp\n    rotate 1\n}\n"
        );

        // /etc/crontab
        self.fichier("/etc/crontab",
            "# /etc/crontab: system-wide crontab\nSHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n# m h dom mon dow user\t\tcommand\n17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n47 6\t* * 7\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )\n52 6\t1 * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )\n0 2\t* * *\troot\t/usr/local/sbin/backup.sh >> /var/log/backup.log 2>&1\n*/5 *\t* * *\troot\t/usr/local/sbin/healthcheck.sh > /dev/null 2>&1\n"
        );

        // /etc/cron.d/e2scrub_all
        self.fichier("/etc/cron.d/e2scrub_all",
            "# Run e2scrub on all mounted filesystems\n30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/e2fsprogs/e2scrub_all_cron\n10 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r\n"
        );

        // /etc/security/limits.conf
        self.fichier("/etc/security/limits.conf",
            "# /etc/security/limits.conf\n# Each line describes a limit for a user in the form:\n# <domain> <type> <item> <value>\n*               soft    nofile          65536\n*               hard    nofile          65536\nroot            soft    nofile          65536\nroot            hard    nofile          65536\n*               soft    nproc           32768\n*               hard    nproc           32768\n"
        );

        // /etc/fail2ban/jail.conf (très réaliste, attrayant pour un attaquant)
        self.fichier("/etc/fail2ban/jail.conf",
            "[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 192.168.0.0/16\nbantime  = 3600\nfindtime = 600\nmaxretry = 5\nbackend = auto\ndestemail = admin@company.internal\nsender = fail2ban@company.internal\naction = %(action_mwl)s\n\n[sshd]\nenabled = true\nport    = ssh\nfilter  = sshd\nlogpath = /var/log/auth.log\nmaxretry = 3\nbantime  = 86400\n\n[nginx-http-auth]\nenabled = false\nport    = http,https\nlogpath = /var/log/nginx/error.log\n"
        );

        // /etc/ufw/ufw.conf
        self.fichier("/etc/ufw/ufw.conf",
            "# /etc/ufw/ufw.conf\nENABLED=yes\nLOGLEVEL=low\n"
        );

        // /proc/version
        self.fichier("/proc/version", &format!(
            "Linux version {kernel} (buildd@lcy02-amd64-059) (x86_64-linux-gnu-gcc-11 (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #91-Ubuntu SMP Fri Jan 12 07:07:48 UTC 2024\n",
            kernel = sys.kernel
        ));

        // /proc/cpuinfo (4 cœurs simulés)
        self.fichier("/proc/cpuinfo",
            "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 158\nmodel name\t: Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz\nstepping\t: 0\nmicrocode\t: 0xb4\ncpu MHz\t\t: 2300.000\ncache size\t: 30720 KB\nphysical id\t: 0\nsiblings\t: 4\ncore id\t\t: 0\ncpu cores\t: 4\nbogomips\t: 4600.00\nFlags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl xtopology cpuid pni pclmulqdq ssse3 cx16 pcid sse4_1 sse4_2 x2apic popcnt aes xsave avx f16c rdrand hypervisor lahf_lm\n\nprocessor\t: 1\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 158\nmodel name\t: Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz\nstepping\t: 0\ncpu MHz\t\t: 2300.000\ncore id\t\t: 1\ncpu cores\t: 4\n\nprocessor\t: 2\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 158\nmodel name\t: Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz\nstepping\t: 0\ncpu MHz\t\t: 2300.000\ncore id\t\t: 2\ncpu cores\t: 4\n\nprocessor\t: 3\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 158\nmodel name\t: Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz\nstepping\t: 0\ncpu MHz\t\t: 2300.000\ncore id\t\t: 3\ncpu cores\t: 4\n"
        );

        // /proc/meminfo
        self.fichier("/proc/meminfo",
            "MemTotal:        8192000 kB\nMemFree:          512000 kB\nMemAvailable:    3400000 kB\nBuffers:          215340 kB\nCached:          3012840 kB\nSwapCached:        12480 kB\nActive:          4820560 kB\nInactive:        1890240 kB\nSwapTotal:       2097148 kB\nSwapFree:        1843200 kB\nDirty:              1280 kB\nWriteback:             0 kB\nAnonPages:       3480320 kB\nMapped:           198400 kB\nShmem:             42040 kB\nKReclaimable:     298400 kB\nSlab:             412800 kB\nVmallocTotal:   34359738367 kB\nVmallocUsed:      124800 kB\nHugePages_Total:       0\nHugePages_Free:        0\nHugepagesize:       2048 kB\n"
        );

        // /proc/uptime (valeur statique mais vraisemblable)
        self.fichier("/proc/uptime", "1234567.89 4850234.12\n");

        // /proc/loadavg
        self.fichier("/proc/loadavg", "0.42 0.38 0.31 2/412 28934\n");

        // ~/.bashrc
        self.fichier(&format!("{}/.bashrc", home),
            "# ~/.bashrc: executed by bash(1) for non-login shells.\ncase $- in\n    *i*) ;;\n      *) return;;\nesac\n\nHISTCONTROL=ignoreboth\nshopt -s histappend\nHISTSIZE=1000\nHISTFILESIZE=2000\n\nshopt -s checkwinsize\n\nif [ -z \"${debian_chroot:-}\" ] && [ -r /etc/debian_chroot ]; then\n    debian_chroot=$(cat /etc/debian_chroot)\nfi\n\ncase \"$TERM\" in\n    xterm-color|*-256color) color_prompt=yes;;\nesac\n\nif [ \"$color_prompt\" = yes ]; then\n    PS1='${debian_chroot:+($debian_chroot)}\\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '\nelse\n    PS1='${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ '\nfi\n\nalias ll='ls -alF'\nalias la='ls -A'\nalias l='ls -CF'\nalias grep='grep --color=auto'\nalias fgrep='fgrep --color=auto'\nalias egrep='egrep --color=auto'\nalias ..='cd ..'\nalias ...='cd ../..'\n\nif [ -f ~/.bash_aliases ]; then\n    . ~/.bash_aliases\nfi\n"
        );

        // ~/.profile
        self.fichier(&format!("{}/.profile", home),
            "# ~/.profile: executed by the command interpreter for login shells.\nif [ -n \"$BASH_VERSION\" ]; then\n    if [ -f \"$HOME/.bashrc\" ]; then\n        . \"$HOME/.bashrc\"\n    fi\nfi\nif [ -d \"$HOME/bin\" ] ; then\n    PATH=\"$HOME/bin:$PATH\"\nfi\nif [ -d \"$HOME/.local/bin\" ] ; then\n    PATH=\"$HOME/.local/bin:$PATH\"\nfi\n"
        );

        // ~/.bash_logout
        self.fichier(&format!("{}/.bash_logout", home),
            "# ~/.bash_logout: executed by bash(1) when login shell exits.\nif [ \"$SHLVL\" = 1 ]; then\n    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q\nfi\n"
        );

        // ~/.vimrc
        self.fichier(&format!("{}/.vimrc", home),
            "\" ~/.vimrc\nset number\nset tabstop=4\nset shiftwidth=4\nset expandtab\nset autoindent\nset hlsearch\nset incsearch\nset ignorecase\nset smartcase\nsyntax on\ncolorscheme desert\nset background=dark\nset ruler\nset showcmd\nset wildmenu\n"
        );

        // ~/.selected_editor
        self.fichier(&format!("{}/.selected_editor", home),
            "# Generated by select-editor\nSELECTED_EDITOR=\"/usr/bin/vim.basic\"\n"
        );

        // ~/.ssh/authorized_keys
        self.fichier(&format!("{}/.ssh/authorized_keys", home),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBvKp7tFjmNnRKMzHXFQXKMp7qFnrCHQLzLm8AjzXvKq admin@workstation\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7x+mNkP2QrL8vF4jT1hY6wZ3uB5cE0aD7nO9pXkMqR2sV jenkins@ci-server\n"
        );

        // ~/.ssh/known_hosts
        self.fichier(&format!("{}/.ssh/known_hosts", home),
            "192.168.10.15 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKnownHostKeyForHoneypot\n192.168.10.20 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7FakeRsaKeyForHoneypotSystem\ngithub.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GkZQ\n"
        );

        // ~/.gnupg/pubring.kbx (fichier binaire simulé — on affiche juste un indicateur)
        self.fichier(&format!("{}/.gnupg/pubring.kbx", home),
            "\x00\x00\x00\x00\x00\x00\x00\x00KBXf\x00\x00\x00\x00"
        );

        // /var/log/auth.log
        self.fichier("/var/log/auth.log",
            "May 10 02:14:33 server sshd[8821]: Invalid user admin from 194.165.16.11 port 49822\nMay 10 02:14:34 server sshd[8821]: Received disconnect from 194.165.16.11 port 49822:11: Bye Bye\nMay 11 03:21:45 server sshd[12847]: Invalid user admin from 45.33.32.156 port 52341\nMay 11 03:21:46 server sshd[12847]: Received disconnect from 45.33.32.156 port 52341:11: Bye Bye\nMay 12 07:03:09 server sshd[13001]: Failed password for root from 103.214.46.12 port 40987\nMay 12 07:03:11 server sshd[13001]: Failed password for root from 103.214.46.12 port 40987\nMay 12 07:03:12 server sshd[13001]: Failed password for root from 103.214.46.12 port 40987\nMay 12 07:03:12 server sshd[13001]: error: maximum authentication attempts exceeded for root from 103.214.46.12 port 40987\nMay 13 08:44:12 server sshd[14203]: Accepted publickey for ubuntu from 192.168.1.10 port 51234 ssh2: ED25519 SHA256:xHFQXKMp7qFnrCHQLzLm8AjzXvKqIBvKp7tFjmNnRKMz\nMay 13 08:44:12 server sshd[14203]: pam_unix(sshd:session): session opened for user ubuntu by (uid=0)\nMay 13 17:55:43 server sshd[18234]: Accepted password for ubuntu from 85.43.12.87 port 60123\nMay 14 09:15:22 server sshd[21045]: Accepted password for ubuntu from 85.43.12.87 port 60891\nMay 14 09:15:22 server sshd[21045]: pam_unix(sshd:session): session opened for user ubuntu by (uid=0)\n"
        );

        // /var/log/syslog
        self.fichier("/var/log/syslog",
            "May 14 08:00:01 server cron[987]: (root) CMD ([ -x /usr/lib/php/sessionclean ] && /usr/lib/php/sessionclean)\nMay 14 08:17:01 server CRON[21234]: (root) CMD (/usr/local/sbin/backup.sh >> /var/log/backup.log 2>&1)\nMay 14 08:17:13 server kernel: [891234.456789] TCP: request_sock_TCP: Possible SYN flooding on port 80.\nMay 14 09:00:01 server systemd[1]: Starting Daily apt download activities...\nMay 14 09:00:07 server systemd[1]: apt-daily.service: Deactivating...\nMay 14 09:15:22 server systemd[1]: Started Session 14 of user ubuntu.\nMay 14 09:30:01 server CRON[22011]: (root) CMD (/usr/local/sbin/healthcheck.sh > /dev/null 2>&1)\nMay 14 10:00:01 server CRON[22344]: (root) CMD ([ -x /usr/sbin/certbot ] && perl -e 'sleep int(rand(43200))' && certbot -q renew)\n"
        );

        // /var/log/dpkg.log
        self.fichier("/var/log/dpkg.log",
            "2026-05-10 06:30:11 startup archives install\n2026-05-10 06:30:14 status installed apt:amd64 2.4.11\n2026-05-10 06:30:16 status installed openssl:amd64 3.0.2-0ubuntu1.15\n2026-05-10 06:30:20 status installed libssl3:amd64 3.0.2-0ubuntu1.15\n2026-05-10 06:30:25 status installed openssh-server:amd64 1:8.9p1-3ubuntu0.10\n2026-05-10 06:30:29 status installed curl:amd64 7.81.0-1ubuntu1.17\n2026-05-10 06:30:31 status installed wget:amd64 1.21.2-2ubuntu1\n2026-05-12 09:14:07 startup archives install\n2026-05-12 09:14:09 status installed linux-image-generic:amd64 5.15.0.107.107\n"
        );

        // /var/log/kern.log
        self.fichier("/var/log/kern.log",
            "May 14 00:00:01 server kernel: [1234567.89] NET: Registered PF_INET6 protocol family\nMay 14 06:00:01 server kernel: [1241567.23] TCP: request_sock_TCP: Possible SYN flooding on port 80. Sending cookies. Check SNMP counters.\nMay 14 09:00:01 server kernel: [1256789.01] EXT4-fs (sda1): re-mounted. Opts: errors=remount-ro. Quota mode: none.\nMay 14 09:15:22 server kernel: [1257234.45] audit: type=1100 audit(1747216522.000:123): pid=21045 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication acct=\"ubuntu\" exe=\"/usr/sbin/sshd\" hostname=85.43.12.87 addr=85.43.12.87 terminal=ssh res=success'\n"
        );

        // /var/log/backup.log
        self.fichier("/var/log/backup.log",
            "[2026-05-14 02:00:01] Début sauvegarde...\n[2026-05-14 02:00:07] Archivage /var/www/html... OK (42M)\n[2026-05/14 02:00:19] Upload S3 bucket company-prod-backups... OK\n[2026-05-14 02:00:23] Nettoyage archives > 30j... 3 fichiers supprimés\n[2026-05-14 02:00:23] Sauvegarde terminée en 22s\n[2026-05-13 02:00:01] Début sauvegarde...\n[2026-05-13 02:00:06] Archivage /var/www/html... OK (41M)\n[2026-05-13 02:00:18] Upload S3 bucket company-prod-backups... OK\n[2026-05-13 02:00:22] Sauvegarde terminée en 21s\n"
        );

        // /var/backups — archives système
        self.fichier("/var/backups/apt.extended_states.1.gz", "[archive gzip binaire]");
        self.fichier("/var/backups/dpkg.status.1.gz",         "[archive gzip binaire]");
        self.fichier("/var/backups/dpkg.diversions.1.gz",     "[archive gzip binaire]");

        // /usr/local/sbin/healthcheck.sh
        self.fichier("/usr/local/sbin/healthcheck.sh",
            "#!/bin/bash\n# Healthcheck system\nif ! systemctl is-active --quiet ssh; then\n    systemctl restart ssh\n    echo \"$(date): sshd relancé\" >> /var/log/healthcheck.log\nfi\ndisk_usage=$(df / | awk 'NR==2 {print $5}' | tr -d '%')\nif [ \"$disk_usage\" -gt 90 ]; then\n    echo \"$(date): ALERTE disque plein ($disk_usage%)\" >> /var/log/healthcheck.log\nfi\n"
        );
    }

    // ── Contenu spécifique : Serveur Web ─────────────────────────────────────

    fn fichiers_web(&mut self, p: &Persona) {
        let home = &p.shell.home;

        // Répertoires
        for dir in &[
            "/etc/nginx", "/etc/nginx/sites-enabled", "/etc/nginx/sites-available",
            "/etc/nginx/conf.d", "/etc/php", "/etc/php/8.2", "/etc/php/8.2/fpm",
            "/var/www", "/var/www/html", "/var/www/html/assets", "/var/www/html/assets/css",
            "/var/www/html/assets/js", "/var/www/html/uploads", "/var/www/html/api",
            "/var/www/html/admin", "/var/log/nginx", "/var/log/php-fpm",
            "/var/backups/webapp", "/etc/cron.d", "/etc/letsencrypt",
            "/etc/letsencrypt/live", "/etc/letsencrypt/live/company.internal",
            "/opt/scripts",
        ] {
            self.dir(dir);
        }

        // nginx.conf
        self.fichier("/etc/nginx/nginx.conf",
            "user www-data;\nworker_processes auto;\npid /run/nginx.pid;\ninclude /etc/nginx/modules-enabled/*.conf;\n\nevents {\n\tworker_connections 1024;\n\tuse epoll;\n\tmulti_accept on;\n}\n\nhttp {\n\tsendfile on;\n\ttcp_nopush on;\n\ttcp_nodelay on;\n\tkeepalive_timeout 65;\n\ttypes_hash_max_size 2048;\n\tserver_tokens off;\n\tclient_max_body_size 64M;\n\n\tinclude /etc/nginx/mime.types;\n\tdefault_type application/octet-stream;\n\n\tlog_format main '$remote_addr - $remote_user [$time_local] \"$request\" '\n\t                '$status $body_bytes_sent \"$http_referer\" '\n\t                '\"$http_user_agent\" \"$http_x_forwarded_for\"';\n\n\taccess_log /var/log/nginx/access.log main;\n\terror_log /var/log/nginx/error.log warn;\n\n\tgzip on;\n\tgzip_vary on;\n\tgzip_proxied any;\n\tgzip_types text/plain text/css application/json application/javascript text/xml;\n\n\tinclude /etc/nginx/conf.d/*.conf;\n\tinclude /etc/nginx/sites-enabled/*;\n}\n"
        );

        // vhost principal
        self.fichier("/etc/nginx/sites-available/company.internal",
            "server {\n\tlisten 80;\n\tserver_name company.internal www.company.internal;\n\treturn 301 https://$host$request_uri;\n}\n\nserver {\n\tlisten 443 ssl http2;\n\tserver_name company.internal www.company.internal;\n\n\tssl_certificate /etc/letsencrypt/live/company.internal/fullchain.pem;\n\tssl_certificate_key /etc/letsencrypt/live/company.internal/privkey.pem;\n\tssl_protocols TLSv1.2 TLSv1.3;\n\tssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;\n\n\troot /var/www/html;\n\tindex index.php index.html;\n\n\tlocation / {\n\t\ttry_files $uri $uri/ /index.php?$query_string;\n\t}\n\n\tlocation ~ \\.php$ {\n\t\tinclude snippets/fastcgi-php.conf;\n\t\tfastcgi_pass unix:/var/run/php/php8.2-fpm.sock;\n\t\tfastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n\t\tinclude fastcgi_params;\n\t}\n\n\tlocation ~ /\\.ht {\n\t\tdeny all;\n\t}\n\n\taccess_log /var/log/nginx/company_access.log;\n\terror_log /var/log/nginx/company_error.log;\n}\n"
        );

        self.fichier("/etc/nginx/sites-enabled/default",
            "server {\n\tlisten 80 default_server;\n\tlisten [::]:80 default_server;\n\troot /var/www/html;\n\tindex index.php index.html;\n\tserver_name _;\n\n\tlocation / {\n\t\ttry_files $uri $uri/ /index.php?$query_string;\n\t}\n\n\tlocation ~ \\.php$ {\n\t\tinclude snippets/fastcgi-php.conf;\n\t\tfastcgi_pass unix:/var/run/php/php8.2-fpm.sock;\n\t}\n\n\tlocation ~ /\\.ht {\n\t\tdeny all;\n\t}\n}\n"
        );

        self.fichier("/etc/nginx/conf.d/security.conf",
            "# Security headers\nadd_header X-Frame-Options \"SAMEORIGIN\" always;\nadd_header X-Content-Type-Options \"nosniff\" always;\nadd_header X-XSS-Protection \"1; mode=block\" always;\nadd_header Referrer-Policy \"no-referrer-when-downgrade\" always;\nadd_header Content-Security-Policy \"default-src 'self' http: https: data: blob: 'unsafe-inline'\" always;\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
        );

        // PHP config
        self.fichier("/etc/php/8.2/fpm/php.ini",
            "[PHP]\nengine = On\nshort_open_tag = Off\nprecision = 14\noutput_buffering = 4096\nzlib.output_compression = Off\nimplicit_flush = Off\nserialize_precision = -1\ndisable_functions = pcntl_alarm,pcntl_fork,pcntl_waitpid,exec,system,passthru,popen\nexpose_php = Off\nmax_execution_time = 60\nmemory_limit = 256M\nerror_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT\ndisplay_errors = Off\nlog_errors = On\nerror_log = /var/log/php-fpm/error.log\npost_max_size = 64M\nupload_max_filesize = 32M\ndate.timezone = Europe/Paris\n"
        );

        // Fichiers web
        self.fichier("/var/www/html/index.php",
            "<?php\n// Main entry point\ndefine('APP_VERSION', '2.4.1');\ndefine('APP_ENV', getenv('APP_ENV') ?: 'production');\n\nrequire_once __DIR__ . '/vendor/autoload.php';\nrequire_once __DIR__ . '/config/app.php';\n\n$app = new Application();\n$app->run();\n"
        );

        self.fichier("/var/www/html/index.html",
            "<!DOCTYPE html>\n<html lang=\"fr\">\n<head>\n<meta charset=\"UTF-8\">\n<title>Company Internal Portal</title>\n</head>\n<body>\n<h1>Company Internal Portal</h1>\n<p>Please <a href=\"/login\">log in</a> to continue.</p>\n</body>\n</html>\n"
        );

        self.fichier("/var/www/html/config.php",
            "<?php\n// Database configuration — DO NOT COMMIT\ndefine('DB_HOST', '192.168.10.15');\ndefine('DB_NAME', 'webapp_prod');\ndefine('DB_USER', 'webapp_user');\ndefine('DB_PASS', 'Pr0d!DbP@ssw0rd_2024');\ndefine('DB_PORT', 3306);\n\ndefine('REDIS_HOST', '127.0.0.1');\ndefine('REDIS_PORT', 6379);\n\ndefine('SECRET_KEY', 'Xk9mN2pQrL8vF4jT1hY6wZ3uB5cE0aD7');\ndefine('JWT_SECRET', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fakesecret');\n"
        );

        self.fichier("/var/www/html/admin/index.php",
            "<?php\n// Admin panel — restricted access\nsession_start();\nif (!isset($_SESSION['admin']) || $_SESSION['admin'] !== true) {\n    header('Location: /login?redirect=/admin');\n    exit;\n}\nrequire_once '../config.php';\n// Dashboard admin\n"
        );

        self.fichier("/var/www/html/api/v1/users.php",
            "<?php\nheader('Content-Type: application/json');\nrequire_once '../../config.php';\n\n$pdo = new PDO(\"mysql:host=\" . DB_HOST . \";dbname=\" . DB_NAME, DB_USER, DB_PASS);\n$stmt = $pdo->prepare('SELECT id, email, created_at FROM users WHERE active = 1 LIMIT 100');\n$stmt->execute();\necho json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));\n"
        );

        // Logs nginx
        self.fichier("/var/log/nginx/access.log",
            "10.0.0.1 - - [14/May/2026:08:01:02 +0000] \"GET / HTTP/1.1\" 200 4218 \"-\" \"Mozilla/5.0 (X11; Linux x86_64)\"\n185.220.101.45 - - [14/May/2026:08:12:33 +0000] \"GET /wp-admin/ HTTP/1.1\" 404 162 \"-\" \"python-requests/2.28.0\"\n185.220.101.45 - - [14/May/2026:08:12:34 +0000] \"POST /wp-login.php HTTP/1.1\" 404 162 \"-\" \"python-requests/2.28.0\"\n185.220.101.45 - - [14/May/2026:08:12:35 +0000] \"GET /.env HTTP/1.1\" 404 162 \"-\" \"python-requests/2.28.0\"\n185.220.101.45 - - [14/May/2026:08:12:36 +0000] \"GET /config.php HTTP/1.1\" 403 162 \"-\" \"python-requests/2.28.0\"\n10.0.0.1 - - [14/May/2026:09:15:02 +0000] \"GET /api/v1/users HTTP/1.1\" 200 3842 \"-\" \"Mozilla/5.0\"\n203.0.113.42 - - [14/May/2026:09:22:07 +0000] \"GET /admin/ HTTP/1.1\" 302 0 \"-\" \"Mozilla/5.0\"\n10.0.0.1 - - [14/May/2026:10:01:55 +0000] \"POST /api/v1/auth/login HTTP/1.1\" 200 512 \"-\" \"axios/1.4.0\"\n"
        );

        self.fichier("/var/log/nginx/error.log",
            "2026/05/14 02:00:01 [notice] 1234#1234: signal process started\n2026/05/14 08:12:33 [error] 5678#5678: *1042 open() \"/var/www/html/wp-admin/\" failed (2: No such file or directory)\n2026/05/14 08:12:35 [error] 5678#5678: *1044 open() \"/var/www/html/.env\" failed (2: No such file or directory)\n2026/05/14 09:30:01 [warn] 5678#5678: *1503 upstream response timeout (110: Connection timed out) while reading response header from upstream\n"
        );

        // Certificats Let's Encrypt (factices)
        self.fichier("/etc/letsencrypt/live/company.internal/fullchain.pem",
            "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKoK7z0Z8QvVMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\n[... certificate data truncated for security ...]\n-----END CERTIFICATE-----\n"
        );

        self.fichier("/etc/letsencrypt/live/company.internal/privkey.pem",
            "-----BEGIN PRIVATE KEY-----\n[ENCRYPTED — DO NOT DISTRIBUTE]\n-----END PRIVATE KEY-----\n"
        );

        // Cron certbot
        self.fichier("/etc/cron.d/certbot",
            "# Renew Let's Encrypt certificates\n0 0,12 * * * root /usr/bin/certbot renew --quiet --post-hook \"systemctl reload nginx\"\n"
        );

        // Backups web
        self.fichier("/var/backups/webapp/webapp-20260512-020001.tar.gz", "[archive gzip 41M]");
        self.fichier("/var/backups/webapp/webapp-20260513-020001.tar.gz", "[archive gzip 41M]");
        self.fichier("/var/backups/webapp/webapp-20260514-020001.tar.gz", "[archive gzip 42M]");

        // Historique bash
        self.fichier(&format!("{}/.bash_history", home),
            "sudo systemctl status nginx\nsudo tail -f /var/log/nginx/error.log\ncd /var/www/html\nls -la\ngit status\ngit pull origin main\ncomposer install --no-dev\nphp artisan migrate --force\nsudo nginx -t\nsudo systemctl reload nginx\nsudo apt update && sudo apt upgrade -y\ndf -h\nfree -m\nnetstat -tlnp\nps aux | grep nginx\nps aux | grep php\nsudo certbot renew --dry-run\ncat /var/log/auth.log | tail -100\ngrep 'Failed password' /var/log/auth.log | wc -l\nsudo fail2ban-client status sshd\ntail -f /var/log/nginx/access.log | grep -v '10.0.0.1'\ncurl -I https://company.internal\nopenssl s_client -connect company.internal:443 2>/dev/null | head -20\n"
        );

        // Script de déploiement
        self.fichier(&format!("{}/deploy.sh", home),
            "#!/bin/bash\n# Script de déploiement production — NE PAS PARTAGER\nset -euo pipefail\n\nREPO=\"git@github.com:company/webapp.git\"\nDEPLOY_DIR=\"/var/www/html\"\nBACKUP_DIR=\"/var/backups/webapp\"\nSLACK_WEBHOOK=\"https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX\"\n\necho \"[$(date)] === Début déploiement ===\"\nmkdir -p $BACKUP_DIR\ntar czf $BACKUP_DIR/webapp-$(date +%Y%m%d-%H%M%S).tar.gz $DEPLOY_DIR\ncd $DEPLOY_DIR\ngit fetch origin\ngit reset --hard origin/main\ncomposer install --no-dev --optimize-autoloader\nphp artisan config:cache\nphp artisan route:cache\nphp artisan migrate --force\nphp artisan queue:restart\nsudo systemctl reload php8.2-fpm\nsudo systemctl reload nginx\ncurl -s -X POST -H 'Content-type: application/json' \\\n    --data \"{\\\"text\\\":\\\"[$(date)] Déploiement production terminé ✅\\\"}\" \\\n    \"$SLACK_WEBHOOK\" > /dev/null\necho \"[$(date)] === Déploiement terminé ===\"\n"
        );

        // scripts opt
        self.fichier("/opt/scripts/monitor.sh",
            "#!/bin/bash\n# Monitoring script — runs every 5min via cron\nHOST=$(hostname)\nMEM=$(free -m | awk 'NR==2{printf \"%d%%\", $3*100/$2}')\nDISK=$(df -h / | awk 'NR==2{print $5}')\nCPU=$(top -bn1 | grep 'Cpu(s)' | awk '{print $2}')\necho \"[$(date)] $HOST — CPU:$CPU MEM:$MEM DISK:$DISK\"\n"
        );
    }

    // ── Contenu spécifique : Base de données ─────────────────────────────────

    fn fichiers_database(&mut self, p: &Persona) {
        let home = &p.shell.home;

        for dir in &[
            "/etc/postgresql", "/etc/postgresql/15", "/etc/postgresql/15/main",
            "/var/lib/postgresql", "/var/lib/postgresql/15", "/var/lib/postgresql/15/main",
            "/var/log/postgresql", "/var/backups/postgres",
            "/etc/cron.d",
        ] {
            self.dir(dir);
        }

        self.fichier("/etc/postgresql/15/main/postgresql.conf",
            "# PostgreSQL 15 configuration file\n\n# Connection\nlisten_addresses = 'localhost'\nport = 5432\nmax_connections = 200\nsuperuser_reserved_connections = 3\n\n# Memory\nshared_buffers = 2GB\neffective_cache_size = 6GB\nwork_mem = 32MB\nmaintenance_work_mem = 512MB\n\n# Checkpoints\ncheckpoint_completion_target = 0.9\nwal_buffers = 64MB\ndefault_statistics_target = 100\nmax_wal_size = 4GB\nmin_wal_size = 1GB\n\n# Logging\nlogging_collector = on\nlog_directory = '/var/log/postgresql'\nlog_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'\nlog_rotation_age = 1d\nlog_rotation_size = 100MB\nlog_min_duration_statement = 1000\nlog_connections = on\nlog_disconnections = on\nlog_lock_waits = on\nlog_timezone = 'Europe/Paris'\n\n# Locale\ndatestyle = 'iso, dmy'\ntimezone = 'Europe/Paris'\nlc_messages = 'en_US.UTF-8'\nlc_monetary = 'fr_FR.UTF-8'\nlc_numeric = 'fr_FR.UTF-8'\nlc_time = 'fr_FR.UTF-8'\ndefault_text_search_config = 'pg_catalog.french'\n\n# Replication\nwal_level = replica\nmax_wal_senders = 3\nmax_replication_slots = 3\n"
        );

        self.fichier("/etc/postgresql/15/main/pg_hba.conf",
            "# PostgreSQL Client Authentication Configuration File\n# TYPE  DATABASE        USER            ADDRESS                 METHOD\nlocal   all             postgres                                peer\nlocal   all             all                                     peer\nhost    all             all             127.0.0.1/32            scram-sha-256\nhost    all             all             ::1/128                 scram-sha-256\nhost    replication     replica_user    192.168.10.21/32        scram-sha-256\nhost    production_db   app_user        192.168.10.0/24         scram-sha-256\nhost    analytics_db    readonly_user   192.168.10.0/24         scram-sha-256\n"
        );

        self.fichier("/etc/postgresql/15/main/pg_ident.conf",
            "# PostgreSQL User Name Maps\n# MAPNAME       SYSTEM-USERNAME   PG-USERNAME\nosmap           postgres          postgres\nosmap           root              postgres\n"
        );

        // .pgpass — leurre principal (mots de passe en clair)
        self.fichier(&format!("{}/.pgpass", home),
            "# PostgreSQL password file — chmod 600\n# hostname:port:database:username:password\nlocalhost:5432:production_db:app_user:Str0ng!Passw0rd_2024\nlocalhost:5432:analytics_db:readonly_user:R3adOnly#Pass\nlocalhost:5432:postgres:postgres:Adm1n@PostgreSQL!\n192.168.10.20:5432:production_db:app_user:Str0ng!Passw0rd_2024\n192.168.10.21:5432:replica_db:replica_user:R3plica@Secret!2024\n"
        );

        // Logs PostgreSQL
        self.fichier("/var/log/postgresql/postgresql-15-main.log",
            "2026-05-14 00:00:01.234 CEST [1234] LOG:  database system is ready to accept connections\n2026-05-14 02:00:01.001 CEST [5678] postgres@production_db LOG:  statement: SELECT pg_size_pretty(pg_database_size('production_db'))\n2026-05-14 02:00:01.412 CEST [5679] postgres@production_db LOG:  statement: CHECKPOINT\n2026-05-14 08:14:33.901 CEST [6012] app_user@production_db LOG:  duration: 1234 ms  statement: SELECT * FROM orders WHERE status='pending' AND created_at > NOW() - INTERVAL '30 days'\n2026-05-14 09:05:17.445 CEST [6102] LOG:  connection received: host=192.168.10.15 port=54321\n2026-05-14 09:05:17.503 CEST [6102] app_user@production_db LOG:  connection authorized: user=app_user database=production_db\n2026-05-14 09:15:22.001 CEST [6234] LOG:  connection received: host=127.0.0.1 port=41234\n"
        );

        // Backups PostgreSQL
        self.fichier("/var/backups/postgres/production_20260512_020001.sql.gz", "[dump postgresql gzip 234M]");
        self.fichier("/var/backups/postgres/production_20260513_020001.sql.gz", "[dump postgresql gzip 235M]");
        self.fichier("/var/backups/postgres/production_20260514_020001.sql.gz", "[dump postgresql gzip 237M]");
        self.fichier("/var/backups/postgres/analytics_20260514_020001.sql.gz",  "[dump postgresql gzip 89M]");

        // Cron backup
        self.fichier("/etc/cron.d/postgresql-backup",
            "# PostgreSQL daily backup\n0 2 * * * postgres /home/postgres/backup.sh >> /var/log/backup.log 2>&1\n30 2 * * 0 postgres /home/postgres/backup_full.sh >> /var/log/backup.log 2>&1\n"
        );

        // Scripts
        self.fichier(&format!("{}/backup.sh", home),
            "#!/bin/bash\n# Backup PostgreSQL incremental — cron: 0 2 * * *\nset -euo pipefail\nPGPASSWORD='Str0ng!Passw0rd_2024'\nexport PGPASSWORD\nBACKUP_DIR='/var/backups/postgres'\nDATE=$(date +%Y%m%d_%H%M%S)\n\nmkdir -p $BACKUP_DIR\npg_dump -U postgres -h localhost production_db | gzip > $BACKUP_DIR/production_${DATE}.sql.gz\npg_dump -U postgres -h localhost analytics_db  | gzip > $BACKUP_DIR/analytics_${DATE}.sql.gz\n\n# Purge des backups > 7 jours\nfind $BACKUP_DIR -name '*.sql.gz' -mtime +7 -delete\n\necho \"[$(date)] Backup terminé: production_${DATE}.sql.gz\"\n"
        );

        self.fichier(&format!("{}/backup_full.sh", home),
            "#!/bin/bash\n# Backup complet hebdomadaire avec envoi S3\nset -euo pipefail\nPGPASSWORD='Str0ng!Passw0rd_2024'\nexport PGPASSWORD\nBACKUP_DIR='/var/backups/postgres'\nDATE=$(date +%Y%m%d)\nS3_BUCKET='s3://company-db-backups'\n\npg_dumpall -U postgres | gzip > $BACKUP_DIR/full_${DATE}.sql.gz\naws s3 cp $BACKUP_DIR/full_${DATE}.sql.gz $S3_BUCKET/weekly/\necho \"[$(date)] Full backup envoyé vers $S3_BUCKET\"\n"
        );

        self.fichier(&format!("{}/maintenance.sql", home),
            "-- Maintenance queries\n-- Taille des tables\nSELECT schemaname, tablename,\n       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size\nFROM pg_tables\nORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC\nLIMIT 20;\n\n-- Connexions actives\nSELECT pid, usename, application_name, client_addr, state, query_start, query\nFROM pg_stat_activity\nWHERE state != 'idle';\n\n-- Index inutilisés\nSELECT s.schemaname, s.relname, s.indexrelname, s.idx_scan\nFROM pg_stat_user_indexes s\nJOIN pg_index i ON s.indexrelid = i.indexrelid\nWHERE s.idx_scan = 0 AND NOT i.indisunique;\n"
        );

        self.fichier(&format!("{}/.psqlrc", home),
            "-- ~/.psqlrc\n\\set PROMPT1 '%[%033[1;32m%]%n@%/%[%033[0m%]> '\n\\set PROMPT2 '... '\n\\set HISTSIZE 1000\n\\set COMP_KEYWORD_CASE upper\n\\timing on\n\\x auto\n\\set VERBOSITY verbose\n"
        );

        // Historique bash
        self.fichier(&format!("{}/.bash_history", home),
            "psql -U postgres\npsql -U postgres -d production_db\npsql -U postgres -d production_db -c \"\\dt\"\npsql -U postgres -c \"SELECT count(*) FROM users;\"\npsql -U postgres -c \"SELECT pg_size_pretty(pg_database_size('production_db'));\"\npsql -U postgres -c \"SELECT pid, usename, query FROM pg_stat_activity WHERE state='active';\"\npg_dump -U postgres production_db > /tmp/prod_backup.sql\nls -lh /var/backups/postgres/\ndu -sh /var/lib/postgresql/\nsudo systemctl status postgresql\ntail -100 /var/log/postgresql/postgresql-15-main.log\nsudo journalctl -u postgresql -n 50\ngrep 'ERROR' /var/log/postgresql/postgresql-15-main.log | tail -20\nvacuumdb -U postgres --all --analyze\nreindexdb -U postgres production_db\nfree -m\ndf -h\nnetstat -tlnp | grep 5432\ncat ~/.pgpass\nbash backup.sh\nbash backup_full.sh\n"
        );
    }

    // ── Contenu spécifique : Machine Développeur ─────────────────────────────

    fn fichiers_dev(&mut self, p: &Persona) {
        let home = &p.shell.home;

        for dir in &[
            &format!("{}/projects", home),
            &format!("{}/projects/webapp", home),
            &format!("{}/projects/webapp/src", home),
            &format!("{}/projects/webapp/src/controllers", home),
            &format!("{}/projects/webapp/src/models", home),
            &format!("{}/projects/webapp/tests", home),
            &format!("{}/projects/webapp/config", home),
            &format!("{}/projects/api", home),
            &format!("{}/projects/api/src", home),
            &format!("{}/projects/infra", home),
            &format!("{}/projects/infra/terraform", home),
            &format!("{}/scripts", home),
            &format!("{}/Downloads", home),
            &format!("{}/bin", home),
        ] {
            self.dir(dir.as_str());
        }

        // .env — leurre principal (faux secrets prod)
        self.fichier(&format!("{}/projects/webapp/.env", home),
            "APP_NAME=CompanyWebApp\nAPP_ENV=production\nAPP_KEY=base64:Xk9mN2pQrL8vF4jT1hY6wZ3uB5cE0aD7\nAPP_DEBUG=false\nAPP_URL=https://webapp.company.internal\n\nDB_CONNECTION=mysql\nDB_HOST=192.168.10.15\nDB_PORT=3306\nDB_DATABASE=webapp_prod\nDB_USERNAME=webapp_user\nDB_PASSWORD=Pr0d!DbP@ssw0rd_2024\n\nREDIS_HOST=127.0.0.1\nREDIS_PASSWORD=R3dis@Pr0d!2024\nREDIS_PORT=6379\n\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nAWS_DEFAULT_REGION=eu-west-1\nAWS_BUCKET=company-prod-assets\nAWS_ENDPOINT=\n\nSTRIPE_KEY=sk_live_51HxampleFakeStripeKeyForHoneypotSystem1234567890\nSTRIPE_WEBHOOK_SECRET=whsec_FakeStripeWebhookSecretForHoneypot\n\nMAIL_MAILER=smtp\nMAIL_HOST=smtp.mailgun.org\nMAIL_PORT=587\nMAIL_USERNAME=postmaster@mail.company.internal\nMAIL_PASSWORD=MailgunSecret2024!\nMAIL_ENCRYPTION=tls\nMAIL_FROM_ADDRESS=noreply@company.internal\n\nGITHUB_TOKEN=ghp_FakeGitHubPersonalAccessTokenForHoneypot123\nSLACK_WEBHOOK=https://hooks.slack.com/services/FAKE/WEBHOOK/URL\nSENTRY_DSN=https://fake@o000000.ingest.sentry.io/0000000\n"
        );

        self.fichier(&format!("{}/projects/webapp/.env.example", home),
            "APP_NAME=WebApp\nAPP_ENV=local\nAPP_KEY=\nAPP_DEBUG=true\nAPP_URL=http://localhost\n\nDB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=webapp\nDB_USERNAME=root\nDB_PASSWORD=\n\nREDIS_HOST=127.0.0.1\nREDIS_PASSWORD=null\nREDIS_PORT=6379\n\nMAIL_MAILER=smtp\nMAIL_HOST=mailhog\nMAIL_PORT=1025\n"
        );

        self.fichier(&format!("{}/projects/webapp/docker-compose.yml", home),
            "version: '3.8'\nservices:\n  app:\n    build:\n      context: .\n      dockerfile: Dockerfile\n    ports:\n      - \"8080:80\"\n    environment:\n      - APP_ENV=production\n      - APP_KEY=${APP_KEY}\n    volumes:\n      - .:/var/www/html\n    depends_on:\n      - db\n      - redis\n    restart: unless-stopped\n  db:\n    image: mysql:8.0\n    environment:\n      MYSQL_ROOT_PASSWORD: R00t!Secret\n      MYSQL_DATABASE: webapp_prod\n      MYSQL_USER: webapp_user\n      MYSQL_PASSWORD: Pr0d!DbP@ssw0rd_2024\n    volumes:\n      - db_data:/var/lib/mysql\n    restart: unless-stopped\n  redis:\n    image: redis:7-alpine\n    command: redis-server --requirepass R3dis@Pr0d!2024\n    restart: unless-stopped\nvolumes:\n  db_data:\n"
        );

        self.fichier(&format!("{}/projects/webapp/Dockerfile", home),
            "FROM php:8.2-fpm-alpine\nRUN apk add --no-cache nginx supervisor curl git nodejs npm\nRUN docker-php-ext-install pdo pdo_mysql redis opcache\nCOPY --from=composer:latest /usr/bin/composer /usr/bin/composer\nWORKDIR /var/www/html\nCOPY . .\nRUN composer install --no-dev --optimize-autoloader\nRUN npm ci && npm run build\nEXPOSE 80\nCMD [\"supervisord\", \"-n\", \"-c\", \"/etc/supervisord.conf\"]\n"
        );

        self.fichier(&format!("{}/projects/webapp/src/controllers/AuthController.php", home),
            "<?php\nnamespace App\\Controllers;\n\nclass AuthController {\n    public function login(Request $request) {\n        $credentials = $request->only('email', 'password');\n        if (auth()->attempt($credentials)) {\n            return response()->json(['token' => auth()->user()->createToken('api')->plainTextToken]);\n        }\n        return response()->json(['error' => 'Unauthorized'], 401);\n    }\n\n    public function logout(Request $request) {\n        $request->user()->currentAccessToken()->delete();\n        return response()->json(['message' => 'Logged out']);\n    }\n}\n"
        );

        self.fichier(&format!("{}/projects/webapp/src/models/User.php", home),
            "<?php\nnamespace App\\Models;\n\nclass User extends Model {\n    protected $fillable = ['name', 'email', 'password', 'role'];\n    protected $hidden   = ['password', 'remember_token'];\n    protected $casts    = ['email_verified_at' => 'datetime', 'password' => 'hashed'];\n\n    public function isAdmin(): bool {\n        return $this->role === 'admin';\n    }\n}\n"
        );

        // Infra / Terraform
        self.fichier(&format!("{}/projects/infra/terraform/main.tf", home),
            "terraform {\n  required_providers {\n    aws = { source = \"hashicorp/aws\", version = \"~> 5.0\" }\n  }\n  backend \"s3\" {\n    bucket = \"company-terraform-state\"\n    key    = \"prod/terraform.tfstate\"\n    region = \"eu-west-1\"\n  }\n}\n\nprovider \"aws\" {\n  region     = var.aws_region\n  access_key = var.aws_access_key\n  secret_key = var.aws_secret_key\n}\n"
        );

        self.fichier(&format!("{}/projects/infra/terraform/terraform.tfvars", home),
            "aws_region     = \"eu-west-1\"\naws_access_key = \"AKIAIOSFODNN7EXAMPLE\"\naws_secret_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\ndb_password    = \"Pr0d!DbP@ssw0rd_2024\"\nvpc_id         = \"vpc-0a1b2c3d4e5f67890\"\nsubnet_ids     = [\"subnet-0a1b2c3d\", \"subnet-1b2c3d4e\"]\n"
        );

        // .gitconfig
        self.fichier(&format!("{}/.gitconfig", home),
            "[user]\n\tname = Dev User\n\temail = dev@company.internal\n[core]\n\teditor = vim\n\tautocrlf = input\n\tpager = less\n[push]\n\tdefault = current\n\tautoSetupRemote = true\n[pull]\n\trebase = false\n[credential]\n\thelper = store\n[alias]\n\tst = status\n\tco = checkout\n\tbr = branch\n\tci = commit\n\tlo = log --oneline --graph --all\n\tdiff-staged = diff --cached\n[color]\n\tui = auto\n[init]\n\tdefaultBranch = main\n"
        );

        // ~/.gitcredentials (leurre — token github en clair)
        self.fichier(&format!("{}/.git-credentials", home),
            "https://dev:ghp_FakeGitHubPersonalAccessTokenForHoneypot123@github.com\nhttps://dev:glpat-FakeGitLabTokenForHoneypotSystem@gitlab.company.internal\n"
        );

        // ~/.ssh/config — accès serveurs
        self.fichier(&format!("{}/.ssh/config", home),
            "# SSH Config\nHost prod-web\n    HostName 192.168.10.10\n    User www-data\n    IdentityFile ~/.ssh/id_ed25519_prod\n    Port 22\n\nHost prod-db\n    HostName 192.168.10.15\n    User postgres\n    IdentityFile ~/.ssh/id_ed25519_prod\n    Port 22\n\nHost bastion\n    HostName vpn.company.internal\n    User devuser\n    IdentityFile ~/.ssh/id_ed25519\n    ServerAliveInterval 60\n\nHost github.com\n    HostName github.com\n    User git\n    IdentityFile ~/.ssh/id_ed25519_github\n\nHost *\n    StrictHostKeyChecking accept-new\n    ServerAliveInterval 120\n"
        );

        // ~/.npmrc
        self.fichier(&format!("{}/.npmrc", home),
            "//registry.npmjs.org/:_authToken=npm_FakeNpmTokenForHoneypotSystem123456789\n//npm.company.internal/:_authToken=npm_FakeInternalRegistryToken\nregistry=https://registry.npmjs.org/\n@company:registry=https://npm.company.internal/\n"
        );

        // ~/.aws/credentials
        self.dir(&format!("{}/.aws", home));
        self.fichier(&format!("{}/.aws/credentials", home),
            "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n\n[prod]\naws_access_key_id = AKIAI0PRODACCESSKEY1234\naws_secret_access_key = ProdSecretAccessKeyForCompanyProductionEnv\n\n[ci]\naws_access_key_id = AKIAICICDPIPELINEKEY56\naws_secret_access_key = CiCdPipelineSecretKeyForGitHubActionsRunner\n"
        );

        self.fichier(&format!("{}/.aws/config", home),
            "[default]\nregion = eu-west-1\noutput = json\n\n[profile prod]\nregion = eu-west-1\noutput = json\nrole_arn = arn:aws:iam::123456789012:role/ProdDeployRole\n"
        );

        // Scripts utiles
        self.fichier(&format!("{}/scripts/deploy_prod.sh", home),
            "#!/bin/bash\n# Déploiement rapide production\nset -euo pipefail\necho \"Deploying to production...\"\nssh prod-web 'cd /var/www/html && git pull && composer install --no-dev && php artisan migrate --force && sudo systemctl reload nginx'\necho \"Done!\"\n"
        );

        self.fichier(&format!("{}/scripts/db_dump.sh", home),
            "#!/bin/bash\n# Dump de la base de données prod en local\nDATE=$(date +%Y%m%d_%H%M%S)\nmysqldump -h 192.168.10.15 -u webapp_user -pPr0d!DbP@ssw0rd_2024 webapp_prod | gzip > ~/Downloads/prod_${DATE}.sql.gz\necho \"Dump saved to ~/Downloads/prod_${DATE}.sql.gz\"\n"
        );

        self.fichier(&format!("{}/scripts/k8s_logs.sh", home),
            "#!/bin/bash\n# Récupère les logs des pods production\nNAMESPACE=${1:-production}\nkubectl --kubeconfig ~/.kube/config get pods -n $NAMESPACE\nkubectl --kubeconfig ~/.kube/config logs -n $NAMESPACE -l app=webapp --since=1h\n"
        );

        // ~/.kube/config (leurre Kubernetes)
        self.dir(&format!("{}/.kube", home));
        self.fichier(&format!("{}/.kube/config", home),
            "apiVersion: v1\nclusters:\n- cluster:\n    server: https://k8s.company.internal:6443\n    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkZha2VDZXJ0aWZpY2F0ZURhdGFGb3JIZW5leXBvdFN5c3RlbQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t\n  name: company-prod\ncontexts:\n- context:\n    cluster: company-prod\n    user: devuser\n    namespace: production\n  name: prod\ncurrent-context: prod\nkind: Config\nusers:\n- name: devuser\n  user:\n    token: eyJhbGciOiJSUzI1NiIsImtpZCI6IkZha2VLOHNUb2tlbkZvckhlbmV5cG90In0.FakePayload.FakeSignature\n"
        );

        // Notes (infos utiles pour un attaquant)
        self.fichier(&format!("{}/notes.txt", home),
            "=== TODO ===\n- Renouveler le certificat SSL avant le 15/06/2026 (certbot sur prod-web)\n- Migrer la DB vers RDS (voir ticket INFRA-4521)\n- MDP prod Redis → voir KeePass entrée 'Redis Prod 2024'\n- Accès VPN → vpn.company.internal, user=devuser, pass demander à Tom\n- Rotation clés AWS prévue le 01/06 — prévenir CI/CD\n- Nexus registry: https://nexus.company.internal (admin/admin123 à changer!)\n\n=== CONTACTS ===\nOps: ops-team@company.internal\nSecurity: security@company.internal (Thomas Leblanc)\nDB Admin: dba@company.internal (Marie Dupont)\n\n=== ACCES SERVEURS ===\nprod-web:  192.168.10.10 (ssh prod-web)\nprod-db:   192.168.10.15 (ssh prod-db)\nstaging:   192.168.10.50 (ssh staging)\nmonitoring: 192.168.10.100 (Grafana: http://192.168.10.100:3000 admin/Grafana@2024)\n"
        );

        // Historique bash
        self.fichier(&format!("{}/.bash_history", home),
            "git clone git@github.com:company/webapp.git projects/webapp\ncd projects/webapp\ngit checkout -b feature/user-auth\ncode .\nnpm install\nnpm run dev\ndocker-compose up -d\ndocker ps\ndocker logs webapp_app_1 -f\ndocker exec -it webapp_db_1 mysql -u webapp_user -pPr0d!DbP@ssw0rd_2024 webapp_prod\ngit status\ngit add src/\ngit commit -m 'feat: add JWT authentication'\ngit push origin feature/user-auth\ncat .env\ncat ~/.aws/credentials\nterraform -chdir=projects/infra/terraform plan\nterraform -chdir=projects/infra/terraform apply -auto-approve\nssh prod-web\nkubectl get pods -n production\nkubectl logs -n production deploy/webapp -f\nbash scripts/deploy_prod.sh\nbash scripts/db_dump.sh\nls ~/Downloads/\n"
        );
    }
}

// ----------------------------------------------------------------------------
// Fonctions utilitaires (privées au module)
// ----------------------------------------------------------------------------

/// Normalise un chemin : supprime les `/` en double, résout `.` et `..`.
fn normaliser(chemin: &str) -> String {
    if chemin.is_empty() {
        return "/".to_string();
    }

    let mut composants: Vec<&str> = Vec::new();
    let absolu = chemin.starts_with('/');

    for partie in chemin.split('/') {
        match partie {
            "" | "." => {}          // on ignore
            ".." => { composants.pop(); } // on remonte
            autre => composants.push(autre),
        }
    }

    let resultat = composants.join("/");
    if absolu {
        format!("/{}", resultat)
    } else if resultat.is_empty() {
        "/".to_string()
    } else {
        resultat
    }
}

/// Retourne le chemin du répertoire parent, ou None si c'est la racine.
fn parent_de(chemin: &str) -> Option<String> {
    let norm = normaliser(chemin);
    if norm == "/" {
        return None;
    }
    let pos = norm.rfind('/')?;
    if pos == 0 {
        Some("/".to_string())
    } else {
        Some(norm[..pos].to_string())
    }
}

/// Si `chemin_complet` est un enfant DIRECT de `parent`, retourne le nom court.
/// Exemple : enfant_direct("/etc", "/etc/passwd") → Some("passwd")
///           enfant_direct("/etc", "/etc/ssh/config") → None (trop profond)
fn enfant_direct<'a>(parent: &str, chemin_complet: &'a str) -> Option<&'a str> {
    let parent_norm = if parent == "/" { "" } else { parent };

    if !chemin_complet.starts_with(parent_norm) {
        return None;
    }

    let reste = &chemin_complet[parent_norm.len()..];

    // Doit commencer par "/" et ne contenir qu'un seul composant
    if let Some(nom) = reste.strip_prefix('/') {
        if !nom.is_empty() && !nom.contains('/') {
            return Some(nom);
        }
    }

    None
}
