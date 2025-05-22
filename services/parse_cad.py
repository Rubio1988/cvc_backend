# services/parse_cad.py
# ---------------------------------
# Plantilla para parsing de archivos CAD: DXF, SVG, STL.
# Convierte diseños en vectores o mallas internas.

import os
from typing import List, Union
# Para DXF
try:
    import ezdxf
except ImportError:
    ezdxf = None
# Para SVG
try:
    from svgpathtools import svg2paths2
except ImportError:
    svg2paths2 = None
# Para STL
try:
    from stl import mesh as stl_mesh
except ImportError:
    stl_mesh = None

# Tipos de retorno genéricos
definition = Union[List[List[float]], List[dict]]

class CADParser:
    """
    Parser de archivos CAD que soporta DXF, SVG y STL.
    Cada método retorna una estructura de vectores o mallas.
    """
    def __init__(self, upload_dir: str = "uploads"):
        self.upload_dir = upload_dir

    def parse(self, filename: str) -> definition:
        """
        Detecta el tipo de archivo por extensión y llama al parser correspondiente.
        """
        ext = os.path.splitext(filename)[1].lower()
        path = os.path.join(self.upload_dir, filename)

        if ext == ".dxf":
            return self._parse_dxf(path)
        elif ext == ".svg":
            return self._parse_svg(path)
        elif ext in [".stl", ".obj"]:
            return self._parse_stl(path)
        else:
            raise ValueError(f"Formato no soportado: {ext}")

    def _parse_dxf(self, path: str) -> List[List[float]]:
        """
        Parse DXF usando ezdxf. Extrae polilíneas y líneas.
        Retorna lista de polilíneas, cada una como lista de [x,y] puntos.
        """
        if ezdxf is None:
            raise ImportError("Instala ezdxf para procesar DXF: pip install ezdxf")
        doc = ezdxf.readfile(path)
        msp = doc.modelspace()
        polylines = []
        for e in msp.query("LWPOLYLINE PLINE LINE"):
            if e.dxftype() == "LWPOLYLINE":
                points = [(pt[0], pt[1]) for pt in e.get_points()]
                polylines.append(points)
            elif e.dxftype() == "LINE":
                start = e.dxf.start
                end = e.dxf.end
                polylines.append([(start.x, start.y), (end.x, end.y)])
        return polylines

    def _parse_svg(self, path: str) -> List[List[complex]]:
        """
        Parse SVG usando svgpathtools. Extrae paths.
        Retorna lista de paths, cada uno como lista de puntos complejos.
        """
        if svg2paths2 is None:
            raise ImportError("Instala svgpathtools para procesar SVG: pip install svgpathtools")
        paths, attributes, svg_att = svg2paths2(path)
        vector_paths = []
        for path_obj in paths:
            coords = [seg.start for seg in path_obj]
            # añadir último punto
            coords.append(path_obj[-1].end)
            vector_paths.append(coords)
        return vector_paths

    def _parse_stl(self, path: str) -> List[List[List[float]]]:
        """
        Parse STL usando numpy-stl. Extrae caras triangulares.
        Retorna lista de triángulos, cada uno con 3 vértices [x,y,z].
        """
        if stl_mesh is None:
            raise ImportError("Instala numpy-stl para procesar STL: pip install numpy-stl")
        mesh = stl_mesh.Mesh.from_file(path)
        triangles = []
        for tri in mesh.vectors:
            # cada tri es array (3,3)
            triangle = [[float(pt[0]), float(pt[1]), float(pt[2])] for pt in tri]
            triangles.append(triangle)
        return triangles

# Uso de ejemplo:
# parser = CADParser(upload_dir="uploads")
# vectores = parser.parse("1234_design.dxf")
# print(vectores)