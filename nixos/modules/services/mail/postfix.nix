{ config, lib, pkgs, ... }:

with lib;

let

  cfg = config.services.postfix;
  user = cfg.user;
  group = cfg.group;
  setgidGroup = cfg.setgidGroup;

  haveAliases = cfg.postmasterAlias != "" || cfg.rootAlias != "" || cfg.extraAliases != "";
  haveTransport = cfg.transport != "";
  haveVirtual = cfg.virtual != "";

  clientAccess =
    if (cfg.dnsBlacklistOverrides != "")
    then [ "check_client_access hash:/etc/postfix/client_access" ]
    else [];

  dnsBl =
    if (cfg.dnsBlacklists != [])
    then [ (concatStringsSep ", " (map (s: "reject_rbl_client " + s) cfg.dnsBlacklists)) ]
    else [];

  clientRestrictions = concatStringsSep ", " (clientAccess ++ dnsBl);

  mainCf = let
    escape = lib.replaceStrings ["$"] ["$$"];
    mkList = items: "\n" + lib.concatMapStringsSep "\n  " escape items;
    mkVal = value:
      if lib.isList value then mkList value
        else " " + (if value == true then "yes"
        else if value == false then "no"
        else toString value);
    mkEntry = name: value: "${escape name} =${mkVal value}";
  in lib.concatStringsSep "\n" (lib.mapAttrsToList mkEntry cfg.config) + "\n" + cfg.extraConfig;

  defaultConf = {
    compatibility_level  = "9999";
    mail_owner           = user;
    default_privs        = "nobody";

    # NixOS specific locations
    data_directory       = "/var/lib/postfix/data";
    queue_directory      = "/var/lib/postfix/queue";

    # Default location of everything in package
    meta_directory       = "${pkgs.postfix}/etc/postfix";
    command_directory    = "${pkgs.postfix}/bin";
    sample_directory     = "/etc/postfix";
    newaliases_path      = "${pkgs.postfix}/bin/newaliases";
    mailq_path           = "${pkgs.postfix}/bin/mailq";
    readme_directory     = false;
    sendmail_path        = "${pkgs.postfix}/bin/sendmail";
    daemon_directory     = "${pkgs.postfix}/libexec/postfix";
    manpage_directory    = "${pkgs.postfix}/share/man";
    html_directory       = "${pkgs.postfix}/share/postfix/doc/html";
    shlib_directory      = false;

    inet_protocols       = mkIf config.networking.enableIPv6 "all";
    mynetworks           = mkIf (cfg.networks != null) cfg.networks;
    mynetworks_style     = mkIf (cfg.networksStyle != "")
                            cfg.networksStyle;
    myhostname           = mkIf (cfg.hostname != "") cfg.hostname;
    mydomain             = mkIf (cfg.domain != "") cfg.domain;
    myorigin             = mkIf (cfg.origin != "") cfg.origin;
    mydestination        = mkIf (cfg.destination != null) cfg.destination;
    relay_domains        = mkIf (cfg.relayDomains != null) cfg.relayDomains;
    relayhost            = if cfg.lookupMX || cfg.relayHost == ""
                             then cfg.relayHost
                             else "[${cfg.relayHost}]";
    mail_spool_directory = "/var/spool/mail/";
    setgid_group         = setgidGroup;

    recipient_delimiter  = mkIf (cfg.recipientDelimiter != "")
                             cfg.recipientDelimiter;
    alias_maps           = mkIf haveAliases "hash:/etc/postfix/aliases";
    transport_maps       = mkIf haveTransport "hash:/etc/postfx/transport";
    virtual_alias_maps   = mkIf haveVirtual "hash:/etc/postfix/virtual";
    smtpd_client_restrictions = mkIf (cfg.dnsBlacklists != [])
                                  clientRestrictions;
  } // (if (cfg.sslCert != "") then {
    smtp_tls_CAfile = cfg.sslCACert;
    smtp_tls_cert_file = cfg.sslCert;
    smtp_tls_key_file = cfg.sslKey;

    smtp_use_tls = true;

    smtpd_tls_CAfile = cfg.sslCACert;
    smtpd_tls_cert_file = cfg.sslCert;
    smtpd_tls_key_file = cfg.sslKey;

    smtpd_use_tls = true;
  } else {});

  masterCfOptions = { lib, ... }: with lib;
    {
      options = {
        type = mkOption {
          type = types.enum [ "inet" "unix" "fifo" "pass" ];
          default = "unix";
          example = "inet";
          description = "The type of the service";
        };
        private = mkOption {
          type = types.bool;
          default = true;
          example = false;
          description = ''
            Whether the service's sockets and storage directory is restricted to
            be only available via the mail system.
          '';
        };
        unpriv = mkOption {
          type = types.bool;
          default = true;
          example = false;
          description = "";
        };
        chroot = mkOption {
          type = types.bool;
          default = false;
          example = true;
          description = ''
            Whether the service is chrooted to have only access to the
            ${optDoc "queueDir"} and the closure of store paths specified by the
            <option>program</option> option.
          '';
        };
        wakeup = mkOption {
          type = types.int;
          default = 0;
          example = 60;
          description = ''
            Automatically wake up the service after the specified number of
            seconds. If <literal>0</literal> is given, never wake the service up.
          '';
        };
        wakeupUnusedComponent = mkOption {
          type = types.bool;
          default = true;
          example = false;
          description = ''
            If set to <literal>false</literal> the component will only be woken up if it is used.
            This is equivalent to postfix' notion of adding a question mark
            behind the wakeup time in <filename>master.cf</filename>
          '';
        };
        maxproc = mkOption {
          type = types.int;
          default = 100;
          example = 1;
          description = ''
            The maximum number of processes to spawn for this service.
            If the value is <literal>0</literal> it doesn't have any limit.
          '';
        };
        command = mkOption {
          type = types.str;
          example = "smtpd";
          description = ''
            A program name specifying a Postfix service/daemon process.
          '';
        };
        args = mkOption {
          type = types.listOf types.str;
          default = [];
          example = [ "-o" "smtp_helo_timeout=5" ];
          description = ''
            Arguments to pass to the <option>command</option>. There is no shell
            processing involved and shell syntax is passed verbatim to the
            process.
          '';
        };
      };
    };

  masterCf = {
    smtp = {
      type = "inet";
      private = false;
      command = "smtpd";
    };
    submission = mkIf (cfg.enableSubmission) {
      type = "inet";
      private = false;
      command = "smtpd";
      args = flatten (mapAttrsToList (x: y: ["-o" (x + "=" + y)]) cfg.submissionOptions);
    };
    pickup = {
      private = false;
      wakeup = 60;
      maxproc = 1;
      command = "pickup";
    };
    cleanup = {
      private = false;
      maxproc = 0;
      command = "cleanup";
    };
    qmgr = {
      private = false;
      wakeup = 300;
      maxproc = 1;
      command = "qmgr";
    };
    tlsmgr = {
      wakeup = 1000;
      wakeupUnusedComponent = false;
      maxproc = 1;
      command = "tlsmgr";
    };
    rewrite = {
      command = "trivial-rewrite";
    };
    bounce = {
      maxproc = 0;
      command = "bounce";
    };
    defer = {
      maxproc = 0;
      command = "bounce";
    };
    trace = {
      maxproc = 0;
      command = "bounce";
    };
    verify = {
      maxproc = 1;
      command = "verify";
    };
    flush = {
      private = false;
      wakeup = 1000;
      wakeupUnusedComponent = false;
      maxproc = 0;
      command = "flush";
    };
    proxymap = {
      command = "proxymap";
    };
    proxywrite = {
      maxproc = 1;
      command = "proxymap";
    };
    smtp = mkIf cfg.enableSmtp {
      command = "smtp";
    };
    relay = mkIf cfg.enableSmtp {
      command = "smtp";
      args = [ "-o" "smtp_fallback_relay=" ];
    };
    showq = {
      private = false;
      command = "showq";
    };
    error = {
      command = "error";
    };
    retry = {
      command = "error";
    };
    discard = {
      command = "discard";
    };
    local = {
      unpriv = false;
      command = "local";
    };
    virtual = {
      unpriv = false;
      command = "virtual";
    };
    lmtp = {
      command = "lmtp";
    };
    anvil = {
      maxproc = 1;
      command = "anvil";
    };
    scache = {
      maxproc = 1;
      command = "scache";
    };
  };

  masterCfHeader = ''
    # ==========================================================================
    # service type  private unpriv  chroot  wakeup  maxproc command + args
    #               (yes)   (yes)   (no)    (never) (100)
    # ==========================================================================
  '';
  masterCfContent = let
    mkBool = b: if b == true then "y" else "n";
    mkWakeup = time: qm: toString time + if qm == true then "" else "?";
    mkArgs = lib.concatStringsSep " "
    mkEntry = name: { type, private, unpriv, chroot, wakeup, wakeupUnusedComponent, maxproc, command, args }:
                "${name} ${type} ${mkBool private} ${mkBool unpriv} ${mkBool chroot}" +
                "${mkWakeup wakeup wakeupUnusedComponent} ${toString maxproc} ${command} ${mkArgs args}";
  in masterCfHeader + lib.concatStringsSep "\n" (lib.mapAttrsToList mkEntry cfg.masterCf) + "\n" + cfg.extraMasterConf;

  aliases =
    optionalString (cfg.postmasterAlias != "") ''
      postmaster: ${cfg.postmasterAlias}
    ''
    + optionalString (cfg.rootAlias != "") ''
      root: ${cfg.rootAlias}
    ''
    + cfg.extraAliases
  ;

  aliasesFile = pkgs.writeText "postfix-aliases" aliases;
  virtualFile = pkgs.writeText "postfix-virtual" cfg.virtual;
  checkClientAccessFile = pkgs.writeText "postfix-check-client-access" cfg.dnsBlacklistOverrides;
  mainCfFile = pkgs.writeText "postfix-main.cf" mainCf;
  masterCfFile = pkgs.writeText "postfix-master.cf" masterCfContent;
  transportFile = pkgs.writeText "postfix-transport" cfg.transport;

in

{

  ###### interface

  options = {

    services.postfix = {

      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Whether to run the Postfix mail server.";
      };

      enableSmtp = mkOption {
        default = true;
        description = "Whether to enable smtp in master.cf.";
      };
      
      enableSubmission = mkOption {
        type = types.bool;
        default = false;
        description = "Whether to enable smtp submission.";
      };

      submissionOptions = mkOption {
        type = types.attrs;
        default = { "smtpd_tls_security_level" = "encrypt";
                    "smtpd_sasl_auth_enable" = "yes";
                    "smtpd_client_restrictions" = "permit_sasl_authenticated,reject";
                    "milter_macro_daemon_name" = "ORIGINATING";
                  };
        description = "Options for the submission config in master.cf";
        example = { "smtpd_tls_security_level" = "encrypt";
                    "smtpd_sasl_auth_enable" = "yes";
                    "smtpd_sasl_type" = "dovecot";
                    "smtpd_client_restrictions" = "permit_sasl_authenticated,reject";
                    "milter_macro_daemon_name" = "ORIGINATING";
                  };
      };

      setSendmail = mkOption {
        type = types.bool;
        default = true;
        description = "Whether to set the system sendmail to postfix's.";
      };

      user = mkOption {
        type = types.str;
        default = "postfix";
        description = "What to call the Postfix user (must be used only for postfix).";
      };

      group = mkOption {
        type = types.str;
        default = "postfix";
        description = "What to call the Postfix group (must be used only for postfix).";
      };

      setgidGroup = mkOption {
        type = types.str;
        default = "postdrop";
        description = "
          How to call postfix setgid group (for postdrop). Should
          be uniquely used group.
        ";
      };

      networks = mkOption {
        type = types.nullOr (types.listOf types.str);
        default = null;
        example = ["192.168.0.1/24"];
        description = "
          Net masks for trusted - allowed to relay mail to third parties -
          hosts. Leave empty to use mynetworks_style configuration or use
          default (localhost-only).
        ";
      };

      networksStyle = mkOption {
        type = types.str;
        default = "";
        description = "
          Name of standard way of trusted network specification to use,
          leave blank if you specify it explicitly or if you want to use
          default (localhost-only).
        ";
      };

      hostname = mkOption {
        type = types.str;
        default = "";
        description ="
          Hostname to use. Leave blank to use just the hostname of machine.
          It should be FQDN.
        ";
      };

      domain = mkOption {
        type = types.str;
        default = "";
        description ="
          Domain to use. Leave blank to use hostname minus first component.
        ";
      };

      origin = mkOption {
        type = types.str;
        default = "";
        description ="
          Origin to use in outgoing e-mail. Leave blank to use hostname.
        ";
      };

      destination = mkOption {
        type = types.nullOr (types.listOf types.str);
        default = null;
        example = ["localhost"];
        description = "
          Full (!) list of domains we deliver locally. Leave blank for
          acceptable Postfix default.
        ";
      };

      relayDomains = mkOption {
        type = types.nullOr (types.listOf types.str);
        default = null;
        example = ["localdomain"];
        description = "
          List of domains we agree to relay to. Default is empty.
        ";
      };

      relayHost = mkOption {
        type = types.str;
        default = "";
        description = "
          Mail relay for outbound mail.
        ";
      };

      lookupMX = mkOption {
        type = types.bool;
        default = false;
        description = "
          Whether relay specified is just domain whose MX must be used.
        ";
      };

      postmasterAlias = mkOption {
        type = types.str;
        default = "root";
        description = "Who should receive postmaster e-mail.";
      };

      rootAlias = mkOption {
        type = types.str;
        default = "";
        description = "
          Who should receive root e-mail. Blank for no redirection.
        ";
      };

      extraAliases = mkOption {
        type = types.lines;
        default = "";
        description = "
          Additional entries to put verbatim into aliases file, cf. man-page aliases(8).
        ";
      };

      config = mkOption {
        type = with types; attrsOf (either bool (either str (listOf str)));
        default = defaultConf;
        description = ''
          The main.cf configuration file as key value set.
        '';
        example = {
          mail_owner = "postfix";
          smtp_use_tls = true;
        };
      };

      extraConfig = mkOption {
        type = types.lines;
        default = "";
        description = "
          Extra lines to be added verbatim to the main.cf configuration file.
        ";
      };

      sslCert = mkOption {
        type = types.str;
        default = "";
        description = "SSL certificate to use.";
      };

      sslCACert = mkOption {
        type = types.str;
        default = "";
        description = "SSL certificate of CA.";
      };

      sslKey = mkOption {
        type = types.str;
        default = "";
        description = "SSL key to use.";
      };

      recipientDelimiter = mkOption {
        type = types.str;
        default = "";
        example = "+";
        description = "
          Delimiter for address extension: so mail to user+test can be handled by ~user/.forward+test
        ";
      };

      virtual = mkOption {
        type = types.lines;
        default = "";
        description = "
          Entries for the virtual alias map, cf. man-page virtual(8).
        ";
      };

      transport = mkOption {
        default = "";
        description = "
          Entries for the transport map, cf. man-page transport(8).
        ";
      };

      dnsBlacklists = mkOption {
        default = [];
        type = with types; listOf string;
        description = "dns blacklist servers to use with smtpd_client_restrictions";
      };

      dnsBlacklistOverrides = mkOption {
        default = "";
        description = "contents of check_client_access for overriding dnsBlacklists";
      };

      masterConfig = mkOption {
        type = types.attrsOf (types.submodule masterCfOptions);
        default = masterCf;
        example =
          { submission = {
              type = "inet";
              args = [ "-o" "smtpd_tls_security_level=encrypt" ];
            }
          };
        description = ''
          An attribute set of service options, which correspond to the service
          definitions usually done within the Postfix
          <filename>master.cf</filename> file.
        '';
      };

      extraMasterConf = mkOption {
        type = types.lines;
        default = "";
        example = "submission inet n - n - - smtpd";
        description = "Extra lines to append to the generated master.cf file.";
      };

      aliasFiles = mkOption {
        type = types.attrsOf types.path;
        default = {};
        description = "Aliases' tables to be compiled and placed into /var/lib/postfix/conf.";
      };

      mapFiles = mkOption {
        type = types.attrsOf types.path;
        default = {};
        description = "Maps to be compiled and placed into /var/lib/postfix/conf.";
      };

    };

  };


  ###### implementation

  config = mkIf config.services.postfix.enable (mkMerge [
    {

      environment = {
        etc = singleton
          { source = "/var/lib/postfix/conf";
            target = "postfix";
          };

        # This makes comfortable for root to run 'postqueue' for example.
        systemPackages = [ pkgs.postfix ];
      };

      services.mail.sendmailSetuidWrapper = mkIf config.services.postfix.setSendmail {
        program = "sendmail";
        source = "${pkgs.postfix}/bin/sendmail";
        group = setgidGroup;
        setuid = false;
        setgid = true;
      };

      users.extraUsers = optional (user == "postfix")
        { name = "postfix";
          description = "Postfix mail server user";
          uid = config.ids.uids.postfix;
          group = group;
        };

      users.extraGroups =
        optional (group == "postfix")
        { name = group;
          gid = config.ids.gids.postfix;
        }
        ++ optional (setgidGroup == "postdrop")
        { name = setgidGroup;
          gid = config.ids.gids.postdrop;
        };

      systemd.services.postfix =
        { description = "Postfix mail server";

          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          path = [ pkgs.postfix ];

          serviceConfig = {
            Type = "forking";
            Restart = "always";
            PIDFile = "/var/lib/postfix/queue/pid/master.pid";
            ExecStart = "${pkgs.postfix}/bin/postfix start";
            ExecStop = "${pkgs.postfix}/bin/postfix stop";
            ExecReload = "${pkgs.postfix}/bin/postfix reload";
          };

          preStart = ''
            # Backwards compatibility
            if [ ! -d /var/lib/postfix ] && [ -d /var/postfix ]; then
              mkdir -p /var/lib
              mv /var/postfix /var/lib/postfix
            fi

            # All permissions set according ${pkgs.postfix}/etc/postfix/postfix-files script
            mkdir -p /var/lib/postfix /var/lib/postfix/queue/{pid,public,maildrop}
            chmod 0755 /var/lib/postfix
            chown root:root /var/lib/postfix

            rm -rf /var/lib/postfix/conf
            mkdir -p /var/lib/postfix/conf
            chmod 0755 /var/lib/postfix/conf
            ln -sf ${pkgs.postfix}/etc/postfix/postfix-files /var/lib/postfix/conf/postfix-files
            ln -sf ${mainCfFile} /var/lib/postfix/conf/main.cf
            ln -sf ${masterCfFile} /var/lib/postfix/conf/master.cf

            ${concatStringsSep "\n" (mapAttrsToList (to: from: ''
              ln -sf ${from} /var/lib/postfix/conf/${to}
              ${pkgs.postfix}/bin/postalias /var/lib/postfix/conf/${to}
            '') cfg.aliasFiles)}
            ${concatStringsSep "\n" (mapAttrsToList (to: from: ''
              ln -sf ${from} /var/lib/postfix/conf/${to}
              ${pkgs.postfix}/bin/postmap /var/lib/postfix/conf/${to}
            '') cfg.mapFiles)}

            mkdir -p /var/spool/mail
            chown root:root /var/spool/mail
            chmod a+rwxt /var/spool/mail
            ln -sf /var/spool/mail /var/

            #Finally delegate to postfix checking remain directories in /var/lib/postfix and set permissions on them
            ${pkgs.postfix}/bin/postfix set-permissions config_directory=/var/lib/postfix/conf
          '';
        };
    }

    (mkIf haveAliases {
      services.postfix.aliasFiles."aliases" = aliasesFile;
    })
    (mkIf haveTransport {
      services.postfix.mapFiles."transport" = transportFile;
    })
    (mkIf haveVirtual {
      services.postfix.mapFiles."virtual" = virtualFile;
    })
    (mkIf (cfg.dnsBlacklists != []) {
      services.postfix.mapFiles."client_access" = checkClientAccessFile;
    })
    (mkIf (cfg.extraConfig != "") {
      warnings = [ "The services.postfix.extraConfig option was deprecated. Please use services.postfix.config instead." ];
    })
  ]);

}
