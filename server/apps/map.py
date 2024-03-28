from apiflask import APIFlask,APIBlueprint
from flask import render_template

bp=APIBlueprint("map",__name__,url_prefix="/map")

@bp.get("/")
def showmap():
    return render_template("/index.html")