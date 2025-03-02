  <script type="text/ecmascript"><![CDATA[
    // ================================
    //       PARAMÈTRES MODIFIABLES
    // ================================
    var cellSize = 8;         // Taille d'une cellule en pixels
    var updateInterval = 100; // Vitesse de rafraîchissement (ms)
    var probAlive = 0.12;     // Pourcentage de cellules vivantes au démarrage

    // Répartition entre les 3 types (la somme doit faire 1)
    var ratioType2 = 0.50; // #42456b (plus grande quantité)
    var ratioType1 = 0.40; // #5209f7 (en plus petite quantité)
    var ratioType3 = 0.10; // #ec421a (très très petite quantité)

    // Couleurs
    var colorBackground = "#0a0a11"; // Fond
    var colorType1 = "#5209f7";
    var colorType2 = "#42456b";
    var colorType3 = "#ec421a";

    // Couleur de la grille
    var colorGrid = "#0d0d14";

    // ================================
    //        VARIABLES GLOBALES
    // ================================
    var svg, cols, rows;
    var grid, nextGrid;
    var cellElements = [];     // Références aux <rect> de chaque cellule
    var gridLinesGroup;        // Groupe pour les lignes de la grille
    var backgroundRect;        // Fond SVG
    var animationId;

    // Initialisation principale
    function init() {
      svg = document.getElementById("golSvg");
      resizeSvg();
      initGrid();
      createSvgCells();
      drawGrid();
      startAnimation();
      window.addEventListener("resize", onResize);
    }

    // Lors du redimensionnement de la fenêtre
    function onResize() {
      stopAnimation();
      resizeSvg();
      initGrid();
      createSvgCells();
      drawGrid();
      startAnimation();
    }

    // Ajuste la taille du SVG et recrée le fond
    function resizeSvg() {
      var width = window.innerWidth;
      var height = window.innerHeight;
      svg.setAttribute("width", width);
      svg.setAttribute("height", height);

      cols = Math.floor(width / cellSize);
      rows = Math.floor(height / cellSize);

      // Réinitialiser le contenu SVG (en dehors du script)
      while (svg.firstChild) {
        svg.removeChild(svg.firstChild);
      }

      // Re-créer le fond
      backgroundRect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      backgroundRect.setAttribute("x", 0);
      backgroundRect.setAttribute("y", 0);
      backgroundRect.setAttribute("width", width);
      backgroundRect.setAttribute("height", height);
      backgroundRect.setAttribute("fill", colorBackground);
      svg.appendChild(backgroundRect);
    }

    // Initialise la grille
    function initGrid() {
      grid = [];
      nextGrid = [];
      for (var r = 0; r < rows; r++) {
        var rowArray = [];
        var nextRowArray = [];
        for (var c = 0; c < cols; c++) {
          rowArray.push(randomCell());
          nextRowArray.push({ alive: false, color: null });
        }
        grid.push(rowArray);
        nextGrid.push(nextRowArray);
      }
    }

    // Crée une cellule aléatoire
    function randomCell() {
      if (Math.random() < probAlive) {
        var r = Math.random();
        if (r < ratioType2) {
          return { alive: true, color: colorType2 };
        } else if (r < ratioType2 + ratioType1) {
          return { alive: true, color: colorType1 };
        } else {
          return { alive: true, color: colorType3 };
        }
      } else {
        return { alive: false, color: null };
      }
    }

    // Crée les éléments SVG pour les cellules
    function createSvgCells() {
      cellElements = [];
      var cellsGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
      cellsGroup.setAttribute("id", "cellsGroup");
      svg.appendChild(cellsGroup);

      for (var r = 0; r < rows; r++) {
        var rowElements = [];
        for (var c = 0; c < cols; c++) {
          var rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
          rect.setAttribute("x", c * cellSize);
          rect.setAttribute("y", r * cellSize);
          rect.setAttribute("width", cellSize);
          rect.setAttribute("height", cellSize);
          rect.setAttribute("fill", grid[r][c].alive ? grid[r][c].color : "none");
          cellsGroup.appendChild(rect);
          rowElements.push(rect);
        }
        cellElements.push(rowElements);
      }
    }

    // Dessine les lignes de la grille
    function drawGrid() {
      if (gridLinesGroup) {
        gridLinesGroup.parentNode.removeChild(gridLinesGroup);
      }
      gridLinesGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
      gridLinesGroup.setAttribute("id", "gridLinesGroup");

      for (var r = 0; r <= rows; r++) {
        var line = document.createElementNS("http://www.w3.org/2000/svg", "line");
        line.setAttribute("x1", 0);
        line.setAttribute("y1", r * cellSize);
        line.setAttribute("x2", cols * cellSize);
        line.setAttribute("y2", r * cellSize);
        line.setAttribute("stroke", colorGrid);
        line.setAttribute("stroke-width", "1");
        gridLinesGroup.appendChild(line);
      }

      for (var c = 0; c <= cols; c++) {
        var line = document.createElementNS("http://www.w3.org/2000/svg", "line");
        line.setAttribute("x1", c * cellSize);
        line.setAttribute("y1", 0);
        line.setAttribute("x2", c * cellSize);
        line.setAttribute("y2", rows * cellSize);
        line.setAttribute("stroke", colorGrid);
        line.setAttribute("stroke-width", "1");
        gridLinesGroup.appendChild(line);
      }
      svg.appendChild(gridLinesGroup);
    }

    // Démarre l'animation
    function startAnimation() {
      animationId = setInterval(function() {
        update();
        updateSvgCells();
      }, updateInterval);
    }

    function stopAnimation() {
      if (animationId) {
        clearInterval(animationId);
        animationId = null;
      }
    }

    // Mise à jour de la grille selon les règles du Game of Life
function update() {
  for (var r = 0; r < rows; r++) {
    for (var c = 0; c < cols; c++) {
      var cell = grid[r][c];
      var neighbors = countNeighbors(r, c);
      
      if (cell.alive) {
        if (neighbors === 2 || neighbors === 3) {
          nextGrid[r][c].alive = true;
          nextGrid[r][c].color = cell.color; // Garde la couleur actuelle
        } else {
          nextGrid[r][c].alive = false;
          nextGrid[r][c].color = null;
        }
      } else {
        if (neighbors === 3) {
          var bornCell = randomCell();
          nextGrid[r][c].alive = true;
          nextGrid[r][c].color = bornCell.color; // Assigne correctement une couleur parmi celles spécifiées
        } else {
          nextGrid[r][c].alive = false;
          nextGrid[r][c].color = null;
        }
      }
    }
  }
  
  var temp = grid;
  grid = nextGrid;
  nextGrid = temp;
}

    // Compte le nombre de voisins vivants d'une cellule
    function countNeighbors(row, col) {
      var count = 0;
      for (var dr = -1; dr <= 1; dr++) {
        for (var dc = -1; dc <= 1; dc++) {
          if (dr === 0 && dc === 0) continue;
          var rr = row + dr;
          var cc = col + dc;
          if (rr >= 0 && rr < rows && cc >= 0 && cc < cols) {
            if (grid[rr][cc].alive) {
              count++;
            }
          }
        }
      }
      return count;
    }

// Met à jour l'affichage des cellules SVG
function updateSvgCells() {
  for (var r = 0; r < rows; r++) {
    for (var c = 0; c < cols; c++) {
      var cell = grid[r][c];
      var rect = cellElements[r][c];
      
      // Assurez-vous que la cellule conserve uniquement une des couleurs spécifiées
      if (cell.alive) {
        if (["#42456b", "#5209f7", "#ec421a"].includes(cell.color)) {
          rect.setAttribute("fill", cell.color);
        } else {
          rect.setAttribute("fill", "#42456b"); // Défaut à la couleur majoritaire
        }
      } else {
        rect.setAttribute("fill", "none");
      }
    }
  }
}
  ]]></script>
