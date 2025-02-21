{pkgs}: {
  deps = [
    pkgs.wireshark
    pkgs.tcpdump
    pkgs.sox
    pkgs.imagemagickBig
    pkgs.glibcLocales
    pkgs.rustc
    pkgs.pkg-config
    pkgs.openssl
    pkgs.libxcrypt
    pkgs.libiconv
    pkgs.cargo
  ];
}
