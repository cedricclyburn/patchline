from jinja2 import Environment, select_autoescape

_env = Environment(autoescape=select_autoescape(default=True))

_TEMPLATE = _env.from_string(
    """<html><body>
<h1>{{ profile.mission }} / {{ profile.vehicle }}</h1>
<table>
{% for wp in profile.waypoints %}<tr><td>{{ wp.name }}</td><td>{{ "%.1f"|format(wp.position.magnitude()) }} m</td></tr>
{% endfor %}</table>
</body></html>"""
)


def render(profile: dict) -> str:
    return _TEMPLATE.render(profile=profile)
