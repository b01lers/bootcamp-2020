with import <nixpkgs> {}; 
mkShell {
  nativeBuildInputs = with buildPackages; [
  ];
  buildInputs = [
    ncurses
  ];
}
