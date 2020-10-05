with import <nixpkgs> {}; 
mkShell {
  nativeBuildInputs = with buildPackages; [
    glibc
  ];
  buildInputs = [
    ncurses
  ];
}
