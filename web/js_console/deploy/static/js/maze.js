// Maze creation from http://logicalmoon.com/2015/06/creating-a-maze-using-javascript/
var maxCols = 36;
var maxRows = 44;

function CreateGrid() {
  var innerHTMLString = "";
  innerHTMLString = "<table>";
  for (var theRow = 1; theRow <= maxRows; theRow++) {
    innerHTMLString += "<tr>";
    for (var theCol = 1; theCol <= maxCols; theCol++) {
      innerHTMLString += '<td id="r';
      innerHTMLString += theRow;
      innerHTMLString += "c";
      innerHTMLString += theCol;
      innerHTMLString += '"></td>';
    }
    innerHTMLString += "</tr>";
  }
  innerHTMLString += "</table>";
  document.getElementById("maze-grid").innerHTML = innerHTMLString;
}

function RemoveWall(row, col) {
  var cell = "r" + row + "c" + col;
  // A north wall would cause a gap to be created so just remove easterly wall.
  if (row === maxRows && col == 1) return;
  if (row === 1) {
    if (col === maxCols) return;
    document.getElementById(cell).style.borderRightStyle = "hidden";
  } else if (col === maxCols) {
    document.getElementById(cell).style.borderTopStyle = "hidden";
  } else {
    if (Math.random() >= 0.5) {
      document.getElementById(cell).style.borderTopStyle = "hidden";
    } else {
      document.getElementById(cell).style.borderRightStyle = "hidden";
    }
  }
}

function Token() {
  $.get("/token", function(data, status) {
    $("#token").html(data);
  });
}

function CreateMaze() {
  for (var theRow = 1; theRow <= maxRows; theRow++) {
    for (var theCol = 1; theCol <= maxCols; theCol++) {
      RemoveWall(theRow, theCol);
    }
  }
}

function CreateAll() {
  Token();
  CreateGrid();
  add_x();
  add_o();
  CreateMaze();
}

window.addEventListener("load", function() {
  CreateAll();
  setInterval(CreateAll, 1000);
});

// CLU \\
let x = maxCols,
  y = 1;

function get_cell(column, row) {
  if (column === 0 || column > maxCols || row === 0 || row > maxRows)
    return null;
  return document.getElementById("r" + row + "c" + column);
}

function remove_x() {
  get_cell(x, y).innerHTML = "";
}

function add_x() {
  get_cell(x, y).innerHTML = '<img src="/static/img/clu_head.jpg" class="x" width="20px" height="20px" />';
}

function add_o() {
  get_cell(1, maxRows).innerHTML = '<p class="o">O</p>';
}

function check_data() {
  if (x === 1 && y === maxRows) {
    $.post("/mem", { token: $("#token").html() }).done(function(data) {
      alert("Memory: " + data);
    });
  }
}

function move_up() {
  let cell = get_cell(x, y);
  if (cell == null) return;
  if (y == 1 || cell.style.borderTopStyle != "hidden") return;
  remove_x();
  y -= 1;
  add_x();
  check_data();
}

function move_down() {
  let cell = get_cell(x, y + 1);
  if (cell == null) return;
  if (y == maxRows || cell.style.borderTopStyle != "hidden") return;
  remove_x();
  y += 1;
  add_x();
  check_data();
}

function move_right() {
  let cell = get_cell(x, y);
  if (cell == null) return;
  if (x == maxCols || cell.style.borderRightStyle != "hidden") return;
  remove_x();
  x += 1;
  add_x();
  check_data();
}

function move_left() {
  let cell = get_cell(x - 1, y);
  if (cell == null) return;
  if (x == 1 || cell.style.borderRightStyle != "hidden") return;
  remove_x();
  x -= 1;
  add_x();
  check_data();
}
