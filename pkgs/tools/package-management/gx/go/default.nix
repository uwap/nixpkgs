# This file was generated by go2nix.
{ stdenv, buildGoPackage, fetchgit
, gx
}:

buildGoPackage rec {
  name = "gx-go-${version}";
  version = "20160611-${stdenv.lib.strings.substring 0 7 rev}";
  rev = "639fc0be1a153c59d8946904cceecf0b66ab2944";

  goPackagePath = "github.com/whyrusleeping/gx-go";

  src = fetchgit {
    inherit rev;
    url = "https://github.com/whyrusleeping/gx-go";
    sha256 = "0qxp7gqrx1rhcbqvp4jdb3gj1dlj200bdc4gq8pfklc8fcz1lc6l";
  };

  goDeps = ../deps.nix;

  extraSrcs = [
    {
      goPackagePath = gx.goPackagePath;
      src = gx.src;
    }
  ];

  meta = with stdenv.lib; {
    description = "A tool for importing go packages into gx";
    homepage = https://github.com/whyrusleeping/gx-go;
    license = licenses.mit;
    maintainer = with maintainers; [ zimbatm ];
  };
}
