{ pkgs }: {
  deps = [
    pkgs.python310
    pkgs.python310Packages.pip
    pkgs.nodejs-18_x
    pkgs.nodePackages.npm
  ];
}
