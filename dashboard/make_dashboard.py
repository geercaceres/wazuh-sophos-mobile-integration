#!/usr/bin/env python3
# make_dashboard.py - part of the Sophos Mobile to Wazuh integration
# Copyright (C) 2026 Gerardo Caceres
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
# Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, see <https://www.gnu.org/licenses/>.
#
"""Generate the Wazuh (OpenSearch Dashboards) saved objects for the Sophos
Mobile integration as an .ndjson file ready for /api/saved_objects/_import.

Usage:
    python3 make_dashboard.py [output.ndjson] [index-pattern-id] [field-suffix]

  index-pattern-id  defaults to "wazuh-alerts-*" (the stock Wazuh pattern)
  field-suffix      "" if data.* strings are mapped as keyword (Wazuh default),
                    ".keyword" if they came through as text
"""
import json
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "sophos-mobile-dashboard.ndjson"
INDEX_PATTERN = sys.argv[2] if len(sys.argv) > 2 else "wazuh-alerts-*"
SFX = sys.argv[3] if len(sys.argv) > 3 else ""

BASE_Q = "rule.groups:sophos_mobile"
PREFIX = "sophos-mobile"
objects = []


def search_source(query):
    return json.dumps({
        "query": {"query": query, "language": "kuery"},
        "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    })


def vis(vid, title, vis_state, query=BASE_Q):
    objects.append({
        "id": f"{PREFIX}-{vid}",
        "type": "visualization",
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)},
        },
        "references": [{
            "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
            "type": "index-pattern",
            "id": INDEX_PATTERN,
        }],
    })
    return f"{PREFIX}-{vid}"


def count_agg():
    return {"id": "1", "enabled": True, "type": "count",
            "schema": "metric", "params": {}}


def terms_agg(aid, field, size=10, schema="segment", order_by="1"):
    return {"id": aid, "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": field, "orderBy": order_by, "order": "desc",
                       "size": size, "otherBucket": False,
                       "otherBucketLabel": "Other", "missingBucket": False,
                       "missingBucketLabel": "Missing"}}


# ---------------------------------------------------------------- metrics row
METRIC_PARAMS = {
    "addTooltip": True, "addLegend": False, "type": "metric",
    "metric": {
        "percentageMode": False, "useRanges": False,
        "colorSchema": "Green to Red", "metricColorMode": "None",
        "colorsRange": [{"from": 0, "to": 10000}],
        "labels": {"show": True}, "invertColors": False,
        "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                  "subText": "", "fontSize": 40},
    },
}


def metric(vid, title, query, subtext=""):
    params = json.loads(json.dumps(METRIC_PARAMS))
    params["metric"]["style"]["subText"] = subtext
    return vis(vid, title,
               {"title": title, "type": "metric", "aggs": [count_agg()],
                "params": params}, query)


p_total = metric("total", "Sophos Mobile - Total alerts", BASE_Q)
p_compl = metric("compliance-count", "Compliance violations",
                 "rule.groups:compliance_violation")
p_threat = metric("threat-count", "Mobile threats (root / malware)",
                  "rule.groups:mobile_threat")
p_high = metric("high-count", "Alerts level 10 and above",
                f"{BASE_Q} and rule.level >= 10")

# ------------------------------------------------------------- time histogram
p_time = vis("over-time", "Sophos alerts over time (by level)", {
    "title": "Sophos alerts over time (by level)",
    "type": "histogram",
    "aggs": [
        count_agg(),
        {"id": "2", "enabled": True, "type": "date_histogram",
         "schema": "segment",
         "params": {"field": "timestamp", "interval": "auto",
                    "min_doc_count": 1, "drop_partials": False,
                    "useNormalizedOpenSearchInterval": True,
                    "scaleMetricValues": False, "extended_bounds": {}}},
        terms_agg("3", "rule.level", 10, "group"),
    ],
    "params": {
        "type": "histogram", "grid": {"categoryLines": False},
        "categoryAxes": [{
            "id": "CategoryAxis-1", "type": "category", "position": "bottom",
            "show": True, "style": {}, "scale": {"type": "linear"},
            "labels": {"show": True, "filter": True, "truncate": 100},
            "title": {}}],
        "valueAxes": [{
            "id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
            "position": "left", "show": True, "style": {},
            "scale": {"type": "linear", "mode": "normal"},
            "labels": {"show": True, "rotate": 0, "filter": False,
                       "truncate": 100},
            "title": {"text": "Alerts"}}],
        "seriesParams": [{
            "show": True, "type": "histogram", "mode": "stacked",
            "data": {"label": "Alerts", "id": "1"},
            "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
            "lineWidth": 2, "showCircles": True}],
        "addTooltip": True, "addLegend": True, "legendPosition": "right",
        "times": [], "addTimeMarker": False, "labels": {"show": False},
        "thresholdLine": {"show": False, "value": 10, "width": 1,
                          "style": "full", "color": "#E7664C"},
    },
})

# ------------------------------------------------------------------- pie: type
PIE_PARAMS = {
    "type": "pie", "addTooltip": True, "addLegend": True,
    "legendPosition": "right", "isDonut": True,
    "labels": {"show": True, "values": True, "last_level": True,
               "truncate": 100},
}

p_record = vis("by-record", "Alerts by record type", {
    "title": "Alerts by record type", "type": "pie",
    "aggs": [count_agg(), terms_agg("2", f"data.sophos_record{SFX}", 10)],
    "params": PIE_PARAMS,
})

p_platform = vis("by-platform", "Devices by platform", {
    "title": "Devices by platform", "type": "pie",
    "aggs": [count_agg(), terms_agg("2", f"data.sophos.os.platform{SFX}", 10)],
    "params": PIE_PARAMS,
})

# ------------------------------------------------------------- tables
TABLE_PARAMS = {
    "perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
    "showTotal": False, "totalFunc": "sum", "percentageCol": "",
    "sort": {"columnIndex": None, "direction": None},
}

p_rules = vis("top-rules", "Top firing rules", {
    "title": "Top firing rules", "type": "table",
    "aggs": [count_agg(),
             terms_agg("2", "rule.id", 15),
             terms_agg("3", "rule.description", 1, "bucket")],
    "params": TABLE_PARAMS,
})

p_devices = vis("top-devices", "Most active devices", {
    "title": "Most active devices", "type": "table",
    "aggs": [count_agg(),
             terms_agg("2", f"data.sophos.location{SFX}", 15)],
    "params": TABLE_PARAMS,
})

p_events = vis("top-event-names", "Most frequent Sophos events", {
    "title": "Most frequent Sophos events", "type": "table",
    "aggs": [count_agg(),
             terms_agg("2", f"data.sophos.name{SFX}", 15)],
    "params": TABLE_PARAMS,
})

p_apps = vis("apps", "App inventory (installed / removed / forbidden)", {
    "title": "App inventory", "type": "table",
    "aggs": [count_agg(),
             terms_agg("2", f"data.sophos.appName{SFX}", 20),
             terms_agg("3", f"data.sophos_record{SFX}", 3, "bucket")],
    "params": TABLE_PARAMS,
}, "rule.groups:mobile_app_inventory")

# --------------------------------------------------------------- saved search
SEARCH_ID = f"{PREFIX}-latest"
objects.append({
    "id": SEARCH_ID,
    "type": "search",
    "attributes": {
        "title": "Sophos Mobile - latest alerts",
        "description": "",
        "hits": 0,
        "columns": ["rule.level", "rule.id", "rule.description",
                    f"data.sophos_record{SFX}"],
        "sort": [["timestamp", "desc"]],
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
            "highlightAll": True, "version": True,
            "query": {"query": BASE_Q, "language": "kuery"},
            "filter": [],
            "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
        })},
    },
    "references": [{
        "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
        "type": "index-pattern",
        "id": INDEX_PATTERN,
    }],
})

# ----------------------------------------------------------------- dashboard
# 48-column grid.
layout = [
    (p_total, 0, 0, 12, 8, "visualization"),
    (p_compl, 12, 0, 12, 8, "visualization"),
    (p_threat, 24, 0, 12, 8, "visualization"),
    (p_high, 36, 0, 12, 8, "visualization"),
    (p_time, 0, 8, 32, 14, "visualization"),
    (p_record, 32, 8, 16, 14, "visualization"),
    (p_rules, 0, 22, 24, 14, "visualization"),
    (p_platform, 24, 22, 12, 14, "visualization"),
    (p_devices, 36, 22, 12, 14, "visualization"),
    (p_events, 0, 36, 24, 14, "visualization"),
    (p_apps, 24, 36, 24, 14, "visualization"),
    (SEARCH_ID, 0, 50, 48, 16, "search"),
]

panels, refs = [], []
for i, (oid, x, y, w, h, otype) in enumerate(layout, start=1):
    ref = f"panel_{i}"
    panels.append({
        "version": "2.13.0",
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
        "panelIndex": str(i),
        "embeddableConfig": {},
        "panelRefName": ref,
    })
    refs.append({"name": ref, "type": otype, "id": oid})

objects.append({
    "id": f"{PREFIX}-dashboard",
    "type": "dashboard",
    "attributes": {
        "title": "Sophos Mobile - Integration",
        "description": ("Events, alerts, compliance state and app inventory pulled "
                        "from Sophos Central / Sophos Mobile via API."),
        "hits": 0,
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"hidePanelTitles": False,
                                   "useMargins": True}),
        "version": 1,
        "timeRestore": True,
        "timeTo": "now",
        "timeFrom": "now-7d",
        "refreshInterval": {"pause": True, "value": 0},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
            "query": {"query": "", "language": "kuery"}, "filter": [],
        })},
    },
    "references": refs,
})

with open(OUT, "w", encoding="utf-8") as f:
    for o in objects:
        f.write(json.dumps(o, ensure_ascii=True) + "\n")

print(f"wrote {len(objects)} saved objects to {OUT}")
print(f"  index-pattern: {INDEX_PATTERN}   field suffix: {SFX!r}")
