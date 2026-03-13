"""
analysis_mon_event.py

Slack 모니터링 채널(Socket Mode)에서 CloudWatch 알람 메시지를 실시간 수신하여
Grafana API + CloudWatch Logs로 부가 정보를 수집하고
Claude AI로 분석한 후 Slack으로 요약 알림을 전송하는 스크립트.

LangChain LCEL 파이프라인:
  AlarmEvent
    → RunnableParallel (Grafana + CloudWatch Logs 병렬 수집)
    → EnrichedContext 구성
    → ChatPromptTemplate | ChatAnthropic.with_structured_output(AnalysisOutput)
    → SlackNotifier
"""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import boto3
import requests
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableLambda, RunnableParallel, RunnablePassthrough
from pydantic import BaseModel, Field
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.socket_mode import SocketModeClient
from slack_sdk.socket_mode.request import SocketModeRequest
from slack_sdk.socket_mode.response import SocketModeResponse

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# 설정
# ─────────────────────────────────────────────

@dataclass
class Config:
    # Slack Bot (입력)
    slack_bot_token: str
    slack_app_token: str
    slack_monitor_channel_id: str

    # Slack Webhook (출력 - 분석 결과)
    slack_webhook_url: str

    # Anthropic Claude
    anthropic_api_key: str
    anthropic_api_url: str

    # Grafana
    grafana_url: str
    grafana_user: str
    grafana_password: str

    # CloudWatch Logs
    aws_default_region: str
    cw_log_window_minutes: int
    ecs_loggroup_lst_path: str  # ECS 서비스 → 로그 그룹 매핑 파일 경로

    # 분석 이력 메모리
    alarm_memory_path: str        # 분석 이력 저장 파일 경로
    alarm_memory_max_records: int # 최대 보관 건수

    # 필터: 처리할 알람 상태 목록 (빈 리스트 = 모두 처리)
    alarm_state_filter: list[str]

    @classmethod
    def from_env(cls) -> Config:
        def require(key: str) -> str:
            value = os.getenv(key)
            if not value:
                raise ValueError(f"필수 환경변수 누락: {key}")
            return value

        state_filter_raw = os.getenv("ALARM_STATE_FILTER", "")
        alarm_state_filter = (
            [s.strip().upper() for s in state_filter_raw.split(",") if s.strip()]
            if state_filter_raw
            else []
        )

        return cls(
            slack_bot_token=require("SLACK_BOT_TOKEN"),
            slack_app_token=require("SLACK_APP_TOKEN"),
            slack_monitor_channel_id=require("SLACK_MONITOR_CHANNEL_ID"),
            slack_webhook_url=require("SLACK_WEBHOOK_URL"),
            anthropic_api_key=require("ANTHROPIC_API_KEY"),
            anthropic_api_url=require("ANTHROPIC_API_URL"),
            grafana_url=require("GRAFANA_URL").rstrip("/"),
            grafana_user=require("GRAFANA_USER"),
            grafana_password=require("GRAFANA_PASSWORD"),
            aws_default_region=os.getenv("AWS_DEFAULT_REGION", "ap-northeast-1"),
            cw_log_window_minutes=int(os.getenv("CW_LOG_WINDOW_MINUTES", "10")),
            ecs_loggroup_lst_path=os.getenv(
                "ECS_LOGGROUP_LST_PATH", "ecs_service_loggroup.lst"
            ),
            alarm_memory_path=os.getenv("ALARM_MEMORY_PATH", "alarm_memory.json"),
            alarm_memory_max_records=int(os.getenv("ALARM_MEMORY_MAX_RECORDS", "100")),
            alarm_state_filter=alarm_state_filter,
        )


# ─────────────────────────────────────────────
# 데이터 모델
# ─────────────────────────────────────────────

@dataclass
class AlarmEvent:
    alarm_name: str
    alarm_description: str
    new_state: str           # "ALARM" | "OK" | "INSUFFICIENT_DATA"
    old_state: str
    state_change_time: datetime
    region: str
    service_name: str        # /ecs/{service_name}/{metric} 에서 추출
    metric_name: str
    trigger_str: str         # Trigger 필드 원문
    raw_slack_text: str      # 원본 Slack 메시지 (디버깅용)


@dataclass
class EnrichedContext:
    alarm: AlarmEvent
    grafana_data: Optional[dict]
    cw_logs: Optional[list[str]]
    cw_metrics: Optional[dict]    # CloudWatch 실제 메트릭 수치 데이터
    history: list[dict]           # 동일 서비스 이전 분석 이력 (최근 N개)
    patterns: dict                # 이전 이력 패턴 통계 (빈도, 반복 여부 등)


class AnalysisOutput(BaseModel):
    """Claude analysis result (for with_structured_output)."""
    summary: str = Field(description="A one-line summary of the issue")
    root_cause: str = Field(description="Analysis of the root cause based on the provided context")
    recommendations: str = Field(description="Specific actionable recommendations for remediation or further investigation")
    sources: list[str] = Field(
        default_factory=list,
        description=(
            "List of data sources actually used in this analysis. "
            "Each entry should identify the source type and key identifier, e.g.: "
            "'CloudWatch Metrics: ECS/ContainerInsights RunningTaskCount', "
            "'CloudWatch Logs: ', "
            "'Grafana Dashboard: Containers file-search'. "
            "Only list sources that contained data relevant to the analysis."
        ),
    )


# ─────────────────────────────────────────────
# Slack 메시지 파싱
# ─────────────────────────────────────────────

class SlackAlarmParser:
    """SNS → Lambda → Slack으로 포워딩된 AWS 알림 메시지 파싱.

    Lambda 코드가 Slack으로 전송하는 모든 AWS SNS 알림 타입 처리:
      - CloudWatch  : *AWS CloudWatch Notification*
      - CodePipeline: *AWS CodePipeline Notification*
      - AutoScaling : *AWS AutoScaling Notification*
      - ElasticBeanstalk, CodeDeploy, ElastiCache, CostManagement, CatchAll
    """

    # Lambda 코드가 생성하는 AWS 알림 텍스트 패턴 (fallback용)
    _AWS_NOTIFICATION_RE = re.compile(r"^\*AWS .+ Notification\*$")
    _CLOUDWATCH_TEXT = "*AWS CloudWatch Notification*"

    # Slack에서 AWS SNS 앱/통합의 username (대소문자 무관)
    _AWS_SNS_APP_NAME = "aws sns"

    def is_aws_notification(self, event: dict) -> bool:
        """AWS SNS 앱이 보낸 메시지이면 모두 처리.

        판별 우선순위:
        1. Slack 앱 username이 "AWS SNS" (대소문자 무관)
        2. text가 *AWS ... Notification* 패턴 (Lambda 포워딩 텍스트 기반)
        """
        # 1. 앱 이름으로 판별 (username 또는 bot_profile.name)
        username = event.get("username", "")
        bot_profile = event.get("bot_profile", {})
        app_name = bot_profile.get("name", username)

        if self._AWS_SNS_APP_NAME in app_name.lower():
            return True

        # 2. 텍스트 패턴으로 판별 (fallback)
        return bool(self._AWS_NOTIFICATION_RE.match(event.get("text", "")))

    def is_cloudwatch_alarm(self, event: dict) -> bool:
        return event.get("text", "") == self._CLOUDWATCH_TEXT

    def parse(self, event: dict) -> Optional[AlarmEvent]:
        if not self.is_aws_notification(event):
            return None

        if self.is_cloudwatch_alarm(event):
            return self._parse_cloudwatch(event)
        return self._parse_generic(event)

    def _parse_cloudwatch(self, event: dict) -> Optional[AlarmEvent]:
        """CloudWatch 알람 전용 파싱 — 상세 필드 추출."""
        attachments = event.get("attachments", [])
        if not attachments:
            logger.warning("CloudWatch 알람 메시지에 attachments 없음")
            return None

        attachment = attachments[0]
        fields = self._extract_fields(attachment)

        # Alarm Name: "<https://...|/ecs/svc/Metric>" → "/ecs/svc/Metric"
        alarm_name = re.sub(
            r"<[^|]+\|([^>]+)>", r"\1", fields.get("Alarm Name", "")
        ).strip()

        # Region: 필드 없으면 ap-northeast-1
        region = fields.get("Region", "ap-northeast-1").strip()

        # 상태
        new_state = fields.get("Current State", "").strip()
        old_state = fields.get("Old State", "").strip()

        # 발생 시각
        state_change_time = self._parse_ts(attachment.get("ts", 0))

        service_name = ""
        ecs_match = re.match(r"/ecs/([^/]+)/", alarm_name)
        if ecs_match:
            service_name = ecs_match.group(1)

        # 메트릭명: "RunningTaskCount < 1.0 (AVERAGE, 5 minutes)"
        trigger_str = fields.get("Trigger", "")
        metric_name = ""
        metric_match = re.match(r"(\S+)\s+", trigger_str)
        if metric_match:
            metric_name = metric_match.group(1)

        return AlarmEvent(
            alarm_name=alarm_name,
            alarm_description=fields.get("Alarm Description", ""),
            new_state=new_state,
            old_state=old_state,
            state_change_time=state_change_time,
            region=region,
            service_name=service_name,
            metric_name=metric_name,
            trigger_str=trigger_str,
            raw_slack_text=json.dumps(event, ensure_ascii=False),
        )

    def _parse_generic(self, event: dict) -> Optional[AlarmEvent]:
        """CloudWatch 외 AWS SNS 알림 공통 파싱 (CodePipeline, AutoScaling 등)."""
        attachments = event.get("attachments", [])
        if not attachments:
            return None

        attachment = attachments[0]
        fields = self._extract_fields(attachment)

        # 알림 타입: "*AWS CodePipeline Notification*" → "AWS CodePipeline Notification"
        notification_type = event.get("text", "").strip("*")

        # color → 상태 매핑 (Lambda 코드 기준)
        color = attachment.get("color", "warning")
        new_state = {"danger": "ALARM", "good": "OK"}.get(color, "WARNING")

        # 서비스명: 타입별 핵심 필드에서 추출
        # ECS Task State Change 이벤트: "Containers" 필드에 실제 컨테이너명이 포함됨
        service_name = (
            fields.get("Containers")
            or fields.get("Pipeline")
            or fields.get("Deployment Group")
            or fields.get("Application")
            or re.sub(r"<[^|]+\|([^>]+)>", r"\1", fields.get("Subscription Name", ""))
            or notification_type
        ).strip()

        # 설명: 모든 필드를 이어서 구성
        description = " | ".join(
            "{}: {}".format(k, re.sub(r"<[^|]+\|([^>]+)>", r"\1", v))
            for k, v in fields.items()
        )

        region = fields.get("Region", "ap-northeast-1").strip()
        state_change_time = self._parse_ts(attachment.get("ts", 0))

        return AlarmEvent(
            alarm_name=notification_type,
            alarm_description=description,
            new_state=new_state,
            old_state="",
            state_change_time=state_change_time,
            region=region,
            service_name=service_name,
            metric_name="",
            trigger_str=description,
            raw_slack_text=json.dumps(event, ensure_ascii=False),
        )

    # ── 내부 유틸 ─────────────────────────────

    @staticmethod
    def _extract_fields(attachment: dict) -> dict[str, str]:
        return {
            f["title"]: f["value"]
            for f in attachment.get("fields", [])
            if "title" in f and "value" in f
        }

    @staticmethod
    def _parse_ts(ts) -> datetime:
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc)
        except (ValueError, TypeError):
            return datetime.now(tz=timezone.utc)


# ─────────────────────────────────────────────
# Grafana 클라이언트
# ─────────────────────────────────────────────

class GrafanaClient:
    """Grafana API로 tag=analysis 대시보드의 실제 메트릭 데이터를 수집하여 LLM에 제공."""

    _ANALYSIS_TAG = "analysis"
    _MAX_PANELS_PER_DASHBOARD = 5   # 대시보드당 최대 패널 수
    _MAX_DATA_POINTS = 20           # 패널당 최대 데이터 포인트 수

    def __init__(self, config: Config) -> None:
        self._base_url = config.grafana_url
        self._session = requests.Session()
        self._session.auth = requests.auth.HTTPBasicAuth(
            config.grafana_user, config.grafana_password
        )
        self._session.headers.update({"Content-Type": "application/json"})

    def get_metrics(self, alarm: AlarmEvent, container_name: str = "") -> Optional[dict]:
        """tag=analysis 대시보드의 패널 쿼리를 실행하여 실제 메트릭 데이터 반환.

        흐름:
        1. tag=analysis 대시보드 검색 (ECS 이벤트이면 container_name으로 추가 필터링)
        2. 각 대시보드의 패널 정의(쿼리 targets) 추출
        3. /api/ds/query 로 실제 메트릭 데이터 조회
        4. LLM이 읽기 쉬운 형태로 포맷하여 반환
        """
        try:
            dashboards = self._search_by_tag(self._ANALYSIS_TAG, query=container_name)
            if not dashboards:
                search_desc = f"tag='{self._ANALYSIS_TAG}'"
                if container_name:
                    search_desc += f", query='{container_name}'"
                logger.info(f"Grafana: {search_desc} 대시보드 없음")
                return None

            logger.info(
                f"Grafana: tag='{self._ANALYSIS_TAG}'"
                + (f", container='{container_name}'" if container_name else "")
                + f" → 대시보드 {len(dashboards)}개 발견"
            )

            # 알람 시각 기준 ±10분 시간 범위 (ms)
            from_ms = int(
                (alarm.state_change_time - timedelta(minutes=10)).timestamp() * 1000
            )
            to_ms = int(
                (alarm.state_change_time + timedelta(minutes=10)).timestamp() * 1000
            )

            dashboard_results = []
            for db in dashboards:
                uid = db.get("uid")
                if not uid:
                    continue

                detail = self._get_dashboard(uid)
                if not detail:
                    continue

                dash_title = detail.get("dashboard", {}).get("title", uid)
                panels = detail.get("dashboard", {}).get("panels", [])
                panel_results = []

                for panel in panels[: self._MAX_PANELS_PER_DASHBOARD]:
                    panel_title = panel.get("title", f"panel_{panel.get('id')}")
                    targets = panel.get("targets", [])
                    datasource = panel.get("datasource")

                    if not targets or not datasource:
                        continue

                    # 패널 정의에서 기본 단위 추출 (쿼리 결과 단위의 fallback)
                    panel_unit = (
                        panel.get("fieldConfig", {})
                            .get("defaults", {})
                            .get("unit", "")
                    )

                    data = self._query_panel(datasource, targets, from_ms, to_ms,
                                             panel_unit=panel_unit)
                    if data:
                        panel_results.append({
                            "panel": panel_title,
                            "data": data,
                        })

                if panel_results:
                    dashboard_results.append({
                        "dashboard": dash_title,
                        "url": f"{self._base_url}/d/{uid}",
                        "panels": panel_results,
                    })

            if not dashboard_results:
                logger.info("Grafana: 패널 데이터 없음 (쿼리 결과 없음)")
                return None

            return {
                "time_range": {
                    "from": (alarm.state_change_time - timedelta(minutes=10)).isoformat(),
                    "to": (alarm.state_change_time + timedelta(minutes=10)).isoformat(),
                },
                "dashboards": dashboard_results,
            }

        except Exception as e:
            logger.warning(f"Grafana 데이터 수집 실패: {e}")
            return None

    # Grafana unit 코드 → 사람이 읽기 쉬운 표현 매핑
    _UNIT_LABELS: dict[str, str] = {
        "percent":      "%",
        "percentunit":  "% (0~1 scale, e.g. 0.85 = 85%)",
        "bytes":        "bytes",
        "decbytes":     "bytes (decimal)",
        "kbytes":       "KB",
        "mbytes":       "MB",
        "gbytes":       "GB",
        "tbytes":       "TB",
        "ms":           "milliseconds",
        "s":            "seconds",
        "µs":           "microseconds",
        "ns":           "nanoseconds",
        "short":        "(dimensionless)",
        "none":         "(dimensionless)",
        "ops":          "ops/s",
        "reqps":        "requests/s",
        "rps":          "r/s",
        "wps":          "w/s",
        "iops":         "IOPS",
        "Bps":          "bytes/s",
        "KBs":          "KB/s",
        "MBs":          "MB/s",
        "GBs":          "GB/s",
        "celsius":      "°C",
        "fahrenheit":   "°F",
    }

    @classmethod
    def _unit_label(cls, unit_code: str) -> str:
        """Grafana unit 코드를 LLM이 이해하기 쉬운 레이블로 변환."""
        return cls._UNIT_LABELS.get(unit_code, unit_code) if unit_code else ""

    def _query_panel(
        self,
        datasource: dict | str,
        targets: list[dict],
        from_ms: int,
        to_ms: int,
        panel_unit: str = "",
    ) -> Optional[list[dict]]:
        """Grafana /api/ds/query 로 패널의 실제 메트릭 데이터 조회."""
        try:
            # datasource가 문자열(이름)이면 dict로 변환
            if isinstance(datasource, str):
                datasource = {"type": "prometheus", "uid": datasource}

            queries = []
            for target in targets:
                if target.get("hide"):
                    continue
                query = {"refId": target.get("refId", "A"), "datasource": datasource}
                # datasource 타입에 따라 쿼리 필드 복사
                for k, v in target.items():
                    if k not in ("refId", "datasource", "hide"):
                        query[k] = v
                queries.append(query)

            if not queries:
                return None

            resp = self._session.post(
                f"{self._base_url}/api/ds/query",
                json={"queries": queries, "from": str(from_ms), "to": str(to_ms)},
                timeout=15,
            )
            resp.raise_for_status()
            return self._parse_query_result(resp.json(), panel_unit=panel_unit)

        except Exception as e:
            logger.debug(f"Grafana 패널 쿼리 실패: {e}")
            return None

    def _parse_query_result(self, raw: dict, panel_unit: str = "") -> list[dict]:
        """Grafana /api/ds/query 응답을 LLM이 읽기 쉬운 형태로 변환.

        단위 추출 우선순위:
        1. schema.fields[1].config.unit  (쿼리 응답에 포함된 필드별 단위)
        2. panel_unit                    (패널 fieldConfig.defaults.unit fallback)
        """
        results = []
        for ref_id, result in raw.get("results", {}).items():
            frames = result.get("frames", [])
            for frame in frames:
                schema = frame.get("schema", {})
                data = frame.get("data", {})
                fields = schema.get("fields", [])
                values = data.get("values", [])

                if len(fields) < 2 or len(values) < 2:
                    continue

                # fields[0] = 시각(timestamp), fields[1:] = 메트릭 값
                time_values = values[0]
                metric_values = values[1] if len(values) > 1 else []

                # 최신 N개 포인트만 사용
                n = self._MAX_DATA_POINTS
                time_values = time_values[-n:]
                metric_values = metric_values[-n:]

                metric_name = (
                    schema.get("name")
                    or (fields[1].get("name") if len(fields) > 1 else ref_id)
                )

                # 단위: 쿼리 응답 우선, 없으면 패널 정의 fallback
                raw_unit = (
                    fields[1].get("config", {}).get("unit", "")
                    if len(fields) > 1 else ""
                ) or panel_unit
                unit_label = self._unit_label(raw_unit)

                # 숫자 리스트 → 최솟값/최댓값/최신값 요약
                numeric = [v for v in metric_values if v is not None]
                summary = {}
                if numeric:
                    summary = {
                        "latest": round(numeric[-1], 4),
                        "min": round(min(numeric), 4),
                        "max": round(max(numeric), 4),
                        "avg": round(sum(numeric) / len(numeric), 4),
                        "points": len(numeric),
                    }

                results.append({
                    "metric": metric_name,
                    "unit": unit_label,       # 단위 레이블 (LLM용)
                    "unit_code": raw_unit,    # 원본 Grafana unit 코드
                    "summary": summary,
                    "recent_values": [
                        {
                            "time": datetime.fromtimestamp(
                                t / 1000, tz=timezone.utc
                            ).strftime("%H:%M:%S"),
                            "value": round(v, 4) if v is not None else None,
                        }
                        for t, v in zip(time_values, metric_values)
                        if t is not None
                    ],
                })
        return results

    def _search_by_tag(self, tag: str, query: str = "") -> list[dict]:
        """tag 기반 대시보드 검색. query가 있으면 제목/설명 검색도 추가."""
        params: dict = {"tag": tag, "type": "dash-db"}
        if query:
            params["query"] = query
        resp = self._session.get(
            f"{self._base_url}/api/search",
            params=params,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()

    def _get_dashboard(self, uid: str) -> Optional[dict]:
        resp = self._session.get(
            f"{self._base_url}/api/dashboards/uid/{uid}",
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()


# ─────────────────────────────────────────────
# 알람 분석 이력 메모리
# ─────────────────────────────────────────────

class AlarmContextMemory:
    """파일 기반 알람 분석 이력 관리.

    분석이 완료될 때마다 결과를 JSON 파일에 누적 저장하고,
    다음 분석 시 동일 서비스의 이전 이력을 컨텍스트로 제공한다.
    """

    def __init__(self, path: str, max_records: int = 100) -> None:
        self._path = path
        self._max_records = max_records
        self._records: list[dict] = self._load()
        logger.info(
            f"AlarmContextMemory: '{path}' 로드 완료 ({len(self._records)}건)"
        )

    def save(self, alarm: AlarmEvent, result: AnalysisOutput) -> None:
        """분석 완료 후 이력을 파일에 저장."""
        record = {
            "timestamp":       alarm.state_change_time.isoformat(),
            "alarm_name":      alarm.alarm_name,
            "service_name":    alarm.service_name,
            "region":          alarm.region,
            "new_state":       alarm.new_state,
            "old_state":       alarm.old_state,
            "summary":         result.summary,
            "root_cause":      result.root_cause,
            "recommendations": result.recommendations,
        }
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records:]
        self._persist()
        logger.info(
            f"AlarmContextMemory: 저장 완료 ({len(self._records)}건 누적)"
        )

    def get_related_history(
        self, alarm: AlarmEvent, limit: int = 5
    ) -> list[dict]:
        """동일 서비스의 이전 분석 이력 반환 (최신 limit개)."""
        related = [
            r for r in self._records
            if r["service_name"] == alarm.service_name
        ]
        history = related[-limit:]
        if history:
            logger.info(
                f"AlarmContextMemory: '{alarm.service_name}' 이력 {len(history)}건 로드"
            )
        return history

    def analyze_patterns(self, alarm: AlarmEvent) -> dict:
        """동일 서비스의 이전 이력을 분석해 패턴 통계를 반환."""
        related = [
            r for r in self._records
            if r["service_name"] == alarm.service_name
        ]
        if not related:
            return {"has_history": False}

        ref = alarm.state_change_time

        def within_hours(ts: str, h: int) -> bool:
            try:
                dt = datetime.fromisoformat(ts)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                delta = (ref - dt).total_seconds()
                return 0 < delta <= h * 3600
            except Exception:
                return False

        alarm_events = [r for r in related if r["new_state"] == "ALARM"]
        counts = {
            "total":       len(related),
            "alarm_total": len(alarm_events),
            "last_1h":     sum(1 for r in related if within_hours(r["timestamp"], 1)),
            "last_24h":    sum(1 for r in related if within_hours(r["timestamp"], 24)),
            "last_7d":     sum(1 for r in related if within_hours(r["timestamp"], 168)),
        }

        recent_states = [r["new_state"] for r in related[-6:]]
        state_pattern = " → ".join(recent_states) if recent_states else "N/A"

        seen: set[str] = set()
        recurring_root_causes: list[str] = []
        for r in reversed(related[-5:]):
            rc = r["root_cause"][:120]
            if rc not in seen:
                seen.add(rc)
                recurring_root_causes.insert(0, rc)

        is_recurring = counts["last_24h"] >= 2
        last = related[-1]

        return {
            "has_history":           True,
            "total_occurrences":     counts["total"],
            "alarm_occurrences":     counts["alarm_total"],
            "occurrences_last_1h":   counts["last_1h"],
            "occurrences_last_24h":  counts["last_24h"],
            "occurrences_last_7d":   counts["last_7d"],
            "is_recurring_issue":    is_recurring,
            "last_occurrence_time":  last["timestamp"],
            "last_occurrence_state": last["new_state"],
            "recent_state_pattern":  state_pattern,
            "recurring_root_causes": recurring_root_causes,
        }

    def _load(self) -> list[dict]:
        try:
            with open(self._path, encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return []
        except json.JSONDecodeError as e:
            logger.warning(f"AlarmContextMemory: 파일 파싱 실패 ({self._path}): {e}")
            return []

    def _persist(self) -> None:
        try:
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(self._records, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"AlarmContextMemory: 저장 실패 ({self._path}): {e}")


# ─────────────────────────────────────────────
# CloudWatch Metrics 클라이언트
# ─────────────────────────────────────────────

class CWMetricsClient:
    """CloudWatch 알람 정의를 조회하고 실제 메트릭 수치 데이터를 수집.

    흐름:
    1. describe_alarms(alarm_name) → Namespace, MetricName, Dimensions, Period, Statistic 획득
    2. get_metric_statistics() → 알람 발생 시각 ±N분 구간의 실제 수치 조회
    """

    def __init__(self, config: Config) -> None:
        self._default_region = config.aws_default_region
        self._window_minutes = config.cw_log_window_minutes

    def get_metrics(self, alarm: AlarmEvent) -> Optional[dict]:
        """알람 이름으로 CloudWatch 알람 정의와 실제 메트릭 데이터를 조회."""
        try:
            region = alarm.region or self._default_region
            session = boto3.Session(region_name=region)
            cw = session.client("cloudwatch")

            # 1. 알람 정의 조회 (Namespace, MetricName, Dimensions, Threshold 등)
            alarm_config = self._describe_alarm(cw, alarm.alarm_name)
            if not alarm_config:
                logger.info(
                    f"CloudWatch Metrics: 알람 정의 없음 ({alarm.alarm_name})"
                )
                return None

            metric_name = alarm_config.get("MetricName", alarm.metric_name)
            namespace   = alarm_config.get("Namespace", "")
            dimensions  = alarm_config.get("Dimensions", [])
            period      = alarm_config.get("Period", 300)
            statistic   = alarm_config.get("Statistic", "Average")
            threshold   = alarm_config.get("Threshold")
            operator    = alarm_config.get("ComparisonOperator", "")

            logger.info(
                f"CloudWatch Metrics: {namespace}/{metric_name} "
                f"(period={period}s, stat={statistic})"
            )

            # 2. 메트릭 통계 조회 (알람 발생 시각 ±N분)
            start = alarm.state_change_time - timedelta(minutes=self._window_minutes)
            end   = alarm.state_change_time + timedelta(minutes=self._window_minutes)

            datapoints = self._get_metric_statistics(
                cw, namespace, metric_name, dimensions, period, statistic, start, end
            )

            return {
                "namespace":           namespace,
                "metric_name":         metric_name,
                "dimensions":          {d["Name"]: d["Value"] for d in dimensions},
                "period_seconds":      period,
                "statistic":           statistic,
                "threshold":           threshold,
                "comparison_operator": operator,
                "time_range": {
                    "from": start.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "to":   end.strftime("%Y-%m-%d %H:%M:%S UTC"),
                },
                "datapoints": datapoints,
            }

        except Exception as e:
            logger.warning(
                f"CloudWatch Metrics 조회 실패 ({alarm.alarm_name}): {e}"
            )
            return None

    def _describe_alarm(self, cw, alarm_name: str) -> Optional[dict]:
        resp = cw.describe_alarms(
            AlarmNames=[alarm_name],
            AlarmTypes=["MetricAlarm"],
        )
        alarms = resp.get("MetricAlarms", [])
        return alarms[0] if alarms else None

    def _get_metric_statistics(
        self,
        cw,
        namespace: str,
        metric_name: str,
        dimensions: list[dict],
        period: int,
        statistic: str,
        start: datetime,
        end: datetime,
    ) -> list[dict]:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start,
            EndTime=end,
            Period=period,
            Statistics=[statistic],
        )
        datapoints = sorted(
            resp.get("Datapoints", []),
            key=lambda x: x["Timestamp"],
        )
        return [
            {
                "time":  dp["Timestamp"].strftime("%H:%M:%S"),
                "value": round(dp.get(statistic, 0), 4),
                "unit":  dp.get("Unit", ""),
            }
            for dp in datapoints
        ]


# ─────────────────────────────────────────────
# CloudWatch Logs 클라이언트
# ─────────────────────────────────────────────

@dataclass
class _LstEntry:
    """ecs_service_loggroup.lst 한 줄 파싱 결과."""
    log_group: str
    region: str
    service_id: str   
    short_name: str    # service_id의 마지막 '/' 이후. 예: "file-search"


class CWLogsClient:
    """CloudWatch Logs에서 알람 관련 로그 그룹을 조회.

    ECS 알람: ecs_service_loggroup.lst 파일 기반으로 application 로그 그룹 조회
    기타 알람: describe_log_groups API로 동적 탐색
    """

    def __init__(self, config: Config) -> None:
        self._default_region = config.aws_default_region
        self._window_minutes = config.cw_log_window_minutes
        self._lst_entries = self._load_lst(config.ecs_loggroup_lst_path)
        logger.info(
            f"CWLogsClient: lst 파일 '{config.ecs_loggroup_lst_path}' "
            f"→ {len(self._lst_entries)}개 항목 로드"
        )

    # ── ECS 판별 ────────────────────────────────

    @staticmethod
    def _is_ecs_alarm(alarm: AlarmEvent) -> bool:
        """alarm_name 이 /ecs/ 로 시작하는지로 ECS 알람 여부 판별."""
        parts = [p for p in alarm.alarm_name.split("/") if p]
        return len(parts) >= 1 and parts[0] == "ecs"

    # ── 공개 메서드 ─────────────────────────────

    def get_logs(self, alarm: AlarmEvent) -> Optional[list[str]]:
        """AlarmEvent 정보를 기반으로 로그 그룹을 찾아 로그를 수집.

        1순위: lst 파일 suffix 매칭 (ECS 서비스)
        2순위: RDS/DocumentDB 전용 탐색 (namespace 기반)
        3순위: describe_log_groups 동적 탐색 (fallback)
        """
        try:
            region = alarm.region or self._default_region
            session = boto3.Session(region_name=region)
            client = session.client("logs")
            cw_client = session.client("cloudwatch")

            # 1. lst 파일로 로그 그룹 조회 (ECS 서비스)
            log_groups = self._lookup_from_lst(alarm.service_name)
            if log_groups:
                logger.info(
                    f"CloudWatch Logs [lst]: service='{alarm.service_name}' "
                    f"→ {log_groups}"
                )
            else:
                # 2. RDS/DocumentDB 전용 탐색
                rds_groups = self._find_rds_docdb_log_groups(
                    client, cw_client, alarm
                )
                if rds_groups:
                    log_groups = rds_groups
                else:
                    # 3. 일반 동적 탐색 (fallback)
                    logger.info(
                        f"CloudWatch Logs [lst]: '{alarm.service_name}' 매핑 없음, "
                        f"동적 탐색으로 fallback"
                    )
                    log_groups = self._find_log_groups_dynamic(client, alarm)

            if not log_groups:
                logger.info(f"CloudWatch Logs: 관련 로그 그룹 없음 ({alarm.alarm_name})")
                return None

            # 2. 시간 범위 설정 (알람 발생 시각 ±N분)
            start_ms = int(
                (alarm.state_change_time - timedelta(minutes=self._window_minutes))
                .timestamp() * 1000
            )
            end_ms = int(
                (alarm.state_change_time + timedelta(minutes=self._window_minutes))
                .timestamp() * 1000
            )

            # 3. 최대 3개 로그 그룹에서 로그 수집 후 병합
            all_messages: list[str] = []
            for log_group in log_groups[:3]:
                msgs = self._fetch_log_events(client, log_group, start_ms, end_ms)
                if msgs:
                    all_messages.append(f"=== {log_group} ({len(msgs)}건) ===")
                    all_messages.extend(msgs)

            logger.info(
                f"CloudWatch Logs: 총 {len(all_messages)}건 수집 "
                f"({len(log_groups)}개 그룹: {log_groups})"
            )
            return all_messages or None

        except Exception as e:
            logger.warning(f"CloudWatch Logs 수집 실패 ({alarm.alarm_name}): {e}")
            return None

    # ── lst 파일 기반 조회 (ECS) ────────────────

    def get_container_name(self, service_name: str) -> str:
        """lst 파일에서 service_name에 매핑된 container short name 반환.

        매칭 규칙:
          - 완전 일치: service_name == short_name
          - suffix 일치: service_name이 "-{short_name}"으로 끝남
        매핑 없으면 빈 문자열 반환.
        """
        svc = service_name.lower()
        for entry in self._lst_entries:
            if svc == entry.short_name or svc.endswith("-" + entry.short_name):
                return entry.short_name
        return ""

    def _lookup_from_lst(self, service_name: str) -> list[str]:
        """lst 파일에서 service_name suffix 매칭으로 로그 그룹 조회.

        매칭 규칙:
          - 완전 일치: service_name == short_name
          - suffix 일치: service_name이 "-{short_name}"으로 끝남
        """
        svc = service_name.lower()
        for entry in self._lst_entries:
            if svc == entry.short_name or svc.endswith("-" + entry.short_name):
                logger.info(
                    f"lst 매칭: '{service_name}' → short_name='{entry.short_name}'"
                    f" → log_group='{entry.log_group}'"
                )
                return [entry.log_group]
        return []

    def _load_lst(self, path: str) -> list[_LstEntry]:
        """ecs_service_loggroup.lst 파싱.

        형식 (탭 구분 4컬럼):
        활성화(true)인 항목만 반환.
        """
        entries: list[_LstEntry] = []
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    cols = line.split("\t")
                    if len(cols) < 4:
                        continue
                    enabled, log_group, region, service_id = (
                        cols[0].strip(),
                        cols[1].strip(),
                        cols[2].strip(),
                        cols[3].strip(),
                    )
                    if enabled.lower() != "true":
                        continue
                    short_name = service_id.split("/")[-1].lower()
                    entries.append(
                        _LstEntry(
                            log_group=log_group,
                            region=region,
                            service_id=service_id,
                            short_name=short_name,
                        )
                    )
        except FileNotFoundError:
            logger.warning(f"CWLogsClient: lst 파일 없음 ({path}) — 동적 탐색만 사용")
        except Exception as e:
            logger.warning(f"CWLogsClient: lst 파일 파싱 실패 ({path}): {e}")
        return entries

    # ── 동적 탐색 (비ECS 또는 lst fallback) ─────

    # RDS/DocumentDB namespace → 로그 그룹 prefix 매핑
    def _find_rds_docdb_log_groups(
        self, logs_client, cw_client, alarm: AlarmEvent
    ) -> list[str]:
        """RDS/DocDB 알람의 DB 식별자를 추출해 해당 로그 그룹을 탐색.

        로그 그룹 구조:
          /aws/docdb/{cluster_or_instance_name}/{logtype}
          /aws/rds/{cluster_or_instance_name}/{logtype}

        탐색 순서:
          1. alarm_name 경로에서 직접 파싱
             /docdb/{id}/...  → docdb 타입, id 추출
             /rds/{id}/...    → rds 타입, id 추출
          2. describe_alarms() Namespace + Dimension (fallback)

        식별자에서 trailing digit 제거 후 prefix 검색:
        """
        db_type, db_id = self._parse_db_id_from_alarm_name(alarm.alarm_name)
        if not db_type or not db_id:
            db_type, db_id = self._parse_db_id_from_cw_alarm(
                cw_client, alarm.alarm_name
            )
        if not db_type or not db_id:
            return []

        logger.info(
            f"CloudWatch Logs [RDS/DocDB]: type={db_type}, db_id={db_id}"
        )

        # trailing digit 제거 → 인스턴스명 prefix 생성
        # 예) sendy-docdb2 → sendy-docdb
        db_prefix = re.sub(r"\d+$", "", db_id)

        root = "/aws/docdb/" if db_type == "docdb" else "/aws/rds/"
        search_prefix = root + db_prefix
        logger.info(f"  → 검색 prefix: {search_prefix}")

        found: dict[str, None] = {}
        try:
            resp = logs_client.describe_log_groups(
                logGroupNamePrefix=search_prefix,
                limit=20,
            )
            for lg in resp.get("logGroups", []):
                found[lg["logGroupName"]] = None
                logger.info(f"  → 로그 그룹 발견: {lg['logGroupName']}")
        except Exception as e:
            logger.debug(f"로그 그룹 탐색 실패 (prefix={search_prefix}): {e}")

        return list(found)

    @staticmethod
    def _parse_db_id_from_alarm_name(alarm_name: str) -> tuple[str, str]:
        """alarm_name 경로에서 DB 타입과 식별자를 직접 추출.

        패턴:
          /docdb/{id}/...     → ("docdb", "{id}")
          /rds/{id}/...       → ("rds",   "{id}")
          /aws/docdb/{id}/... → ("docdb", "{id}")
          /aws/rds/{id}/...   → ("rds",   "{id}")
        """
        m = re.search(r"(?:^|/)docdb/([^/]+)/", alarm_name)
        if m:
            return "docdb", m.group(1)
        m = re.search(r"(?:^|/)rds/([^/]+)/", alarm_name)
        if m:
            return "rds", m.group(1)
        return "", ""

    @staticmethod
    def _parse_db_id_from_cw_alarm(cw_client, alarm_name: str) -> tuple[str, str]:
        """describe_alarms() Namespace + Dimension에서 DB 식별자 추출 (fallback)."""
        try:
            resp = cw_client.describe_alarms(
                AlarmNames=[alarm_name],
                AlarmTypes=["MetricAlarm"],
            )
            configs = resp.get("MetricAlarms", [])
            if not configs:
                return "", ""

            cfg = configs[0]
            namespace = cfg.get("Namespace", "").lower()
            dimensions = {d["Name"]: d["Value"] for d in cfg.get("Dimensions", [])}
            db_id = next(
                (
                    dimensions[k]
                    for k in (
                        "DBClusterIdentifier",
                        "DBInstanceIdentifier",
                        "DbClusterIdentifier",
                    )
                    if k in dimensions
                ),
                None,
            )
            if not db_id:
                return "", ""

            if "docdb" in namespace:
                return "docdb", db_id
            if "rds" in namespace or "aurora" in namespace:
                return "rds", db_id
            return "", ""

        except Exception as e:
            logger.debug(f"describe_alarms 실패 ({alarm_name}): {e}")
            return "", ""

    def _find_log_groups_dynamic(
        self, client, alarm: AlarmEvent
    ) -> list[str]:
        """describe_log_groups API로 alarm 관련 로그 그룹 동적 탐색."""
        patterns: list[str] = []

        # alarm_name 경로에서 서비스 prefix 추출
        if alarm.alarm_name and "/" in alarm.alarm_name:
            parts = [p for p in alarm.alarm_name.split("/") if p]
            if len(parts) >= 2:
                patterns.append("/" + "/".join(parts[:2]))

        if alarm.service_name:
            patterns.append(alarm.service_name)

        patterns = list(dict.fromkeys(p for p in patterns if p))
        logger.info(f"CloudWatch Logs [동적 탐색]: 패턴 = {patterns}")

        found: dict[str, None] = {}
        for pattern in patterns:
            try:
                resp = client.describe_log_groups(
                    logGroupNamePattern=pattern,
                    limit=5,
                )
                for lg in resp.get("logGroups", []):
                    found[lg["logGroupName"]] = None
            except Exception as e:
                logger.debug(f"로그 그룹 검색 실패 (pattern={pattern}): {e}")
        return list(found)

    def _fetch_log_events(
        self, client, log_group: str, start_ms: int, end_ms: int
    ) -> list[str]:
        resp = client.filter_log_events(
            logGroupName=log_group,
            startTime=start_ms,
            endTime=end_ms,
            limit=200,
        )
        return [e["message"] for e in resp.get("events", [])]


# ─────────────────────────────────────────────
# Slack 알림 전송
# ─────────────────────────────────────────────

_STATE_EMOJI = {
    "ALARM":             ":red_circle:",
    "OK":                ":large_green_circle:",
    "INSUFFICIENT_DATA": ":large_yellow_circle:",
    "WARNING":           ":large_yellow_circle:",
}


class SlackNotifier:
    """분석 결과를 Slack Block Kit으로 전송."""

    def __init__(self, config: Config) -> None:
        self._webhook_url = config.slack_webhook_url

    def send(self, alarm: AlarmEvent, result: AnalysisOutput) -> None:
        state_emoji = _STATE_EMOJI.get(alarm.new_state, ":white_circle:")
        occurred = alarm.state_change_time.strftime("%Y-%m-%d %H:%M:%S UTC")

        blocks = [
            # ── 헤더: 알람명 + 상태 ──────────────────────
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{state_emoji}  {alarm.alarm_name} Anyalysis Result",
                },
            },
            # ── 알람 메타 정보 ────────────────────────────
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Status*\n`{alarm.old_state or 'N/A'}` → `{alarm.new_state}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Service*\n`{alarm.service_name or 'N/A'}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Region*\n`{alarm.region}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Occurred*\n{occurred}",
                    },
                ],
            },
            {"type": "divider"},
            # ── Summary ───────────────────────────────────
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":clipboard: *Summary*\n{result.summary}",
                },
            },
            # ── Root Cause ────────────────────────────────
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":mag: *Root Cause*\n{result.root_cause}",
                },
            },
            # ── Recommendations ───────────────────────────
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":white_check_mark: *Recommendations*\n{result.recommendations}",
                },
            },
            {"type": "divider"},
        ]

        # ── 분석에 사용된 출처 ─────────────────────────────
        if result.sources:
            sources_text = "\n".join(f"• {s}" for s in result.sources)
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":books: *Data Sources Used*\n{sources_text}",
                },
            })

        # ── Footer ────────────────────────────────────────
        footer_elements = [
            {
                "type": "mrkdwn",
                "text": ":robot_face: _Automated Monitoring Report_",
            }
        ]
        if alarm.trigger_str:
            footer_elements.append({
                "type": "mrkdwn",
                "text": f":bell: *Trigger:* {alarm.trigger_str}",
            })
        blocks.append({
            "type": "context",
            "elements": footer_elements,
        })

        payload = {
            # fallback text (알림 푸시/미리보기용)
            "text": f"{state_emoji} [{alarm.new_state}] {alarm.alarm_name}",
            "blocks": blocks,
        }

        resp = requests.post(
            self._webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if resp.status_code != 200:
            logger.error(f"Slack 전송 실패: {resp.status_code} {resp.text}")
        else:
            logger.info(f"Slack 알림 전송 완료: {alarm.alarm_name}")


# ─────────────────────────────────────────────
# LangChain 프롬프트
# ─────────────────────────────────────────────

_SYSTEM_PROMPT = """
## role and expertise
    - You are an expert Site Reliability Engineer (SRE) or DevOps Engineer specialized in root cause analysis for distributed cloud systems. Your mission is to analyze monitoring events from service and identify the underlying causes of incidents based on the provided context or facts, not just symptoms.
    - You are expert in AWS services, especially CloudWatch, ECS, Lambda, SNS, and various application monitoring tools.
    - You never guess or fabricate to analyze data. If the provided data is insufficient to determine a root cause, you clearly state that the root cause is unknown and recommend further investigation with more data.

## analysis requirements
    - Focus on diagnosing the ** root cause of the issue ** based on the provided context, which includes CloudWatch alarm details, Grafana metrics, and CloudWatch logs.


## output format
    - All output must be in English and human-readable text as pretty printed text.
    - Highlight the most likely root cause(s) and explain your reasoning based on the evidence from the metrics and logs.
    - Regarding recommendations or root_cause, limit to 3 specific, actionable items that engineers can investigate or implement to resolve the issue or mitigate its impact, especially code aspect.
    - Make **simple responses under 3000 chars** that are concise and to the point, avoiding unnecessary technical jargon or overcomplicated explanations. Focus on clear, actionable insights that can be quickly understood by engineers who may not have deep expertise in the specific technologies involved.
    - Return a slack Message with the following structure:
    {{
        "summary": "a one-line summary of the issue",
        "root_cause": "analysis of the root cause based on the provided context",
        "recommendations": "specific actionable recommendations for remediation or further investigation",
        "sources": ["list of data sources actually referenced in this analysis, e.g. 'CloudWatch Metrics: ECS/ContainerInsights RunningTaskCount', 'CloudWatch Logs: /ecs/.../file-search (42 entries)', 'Grafana Dashboard: Containers file-search'"]
    }}
    - For sources, only include data that was actually available AND used as evidence. Omit sources that had no data or were not relevant to the analysis.
"""

_PROMPT_TEMPLATE = ChatPromptTemplate.from_messages([
    ("system", _SYSTEM_PROMPT),
    ("human", "{context}"),
])


def _format_grafana_section(grafana_data: dict) -> str:
    """Grafana 메트릭 데이터를 LLM이 읽기 쉬운 텍스트로 변환."""
    lines = []
    time_range = grafana_data.get("time_range", {})
    lines.append(
        f"Time range: {time_range.get('from', '?')} ~ {time_range.get('to', '?')}"
    )

    for db in grafana_data.get("dashboards", []):
        lines.append(f"\n[Dashboard] {db['dashboard']}  ({db['url']})")
        for panel in db.get("panels", []):
            lines.append(f"  Panel: {panel['panel']}")
            for metric in panel.get("data", []):
                s = metric.get("summary", {})
                unit = metric.get("unit", "")
                unit_str = f" [{unit}]" if unit else ""

                # 메트릭명 + 단위 표시
                lines.append(f"    Metric: {metric['metric']}{unit_str}")

                # 요약 통계 (단위 포함)
                if s:
                    lines.append(
                        f"      latest={s['latest']}{unit_str}"
                        f"  min={s['min']}{unit_str}"
                        f"  max={s['max']}{unit_str}"
                        f"  avg={s['avg']}{unit_str}"
                        f"  ({s['points']} pts)"
                    )

                # 최근 값 추이 (최대 10개, 단위 포함)
                recent = metric.get("recent_values", [])[-10:]
                if recent:
                    trend = "  ".join(
                        f"{p['time']}:{p['value']}{unit_str}" for p in recent
                    )
                    lines.append(f"      Trend: {trend}")
    return "\n".join(lines)


def _build_context_text(ctx: EnrichedContext, window_minutes: int) -> str:
    """Build English prompt context for Claude from EnrichedContext."""
    alarm = ctx.alarm

    grafana_section = (
        _format_grafana_section(ctx.grafana_data)
        if ctx.grafana_data
        else "No data collected or collection failed."
    )

    logs_section = (
        "\n".join(ctx.cw_logs[-50:])   # latest 50 lines
        if ctx.cw_logs
        else "No logs collected or collection failed."
    )

    # ── CloudWatch Metrics Section ───────────────────────────────
    if ctx.cw_metrics:
        m = ctx.cw_metrics
        dims = ", ".join(f"{k}={v}" for k, v in m.get("dimensions", {}).items())
        dp_lines = "  ".join(
            f"{dp['time']}:{dp['value']}{(' ' + dp['unit']) if dp.get('unit') else ''}"
            for dp in m.get("datapoints", [])
        ) or "(no datapoints in range)"
        cw_metrics_section = (
            f"- Namespace: {m['namespace']}\n"
            f"- MetricName: {m['metric_name']}\n"
            f"- Dimensions: {dims or 'N/A'}\n"
            f"- Statistic: {m['statistic']} (period={m['period_seconds']}s)\n"
            f"- Threshold: {m['comparison_operator']} {m['threshold']}\n"
            f"- Time Range: {m['time_range']['from']} ~ {m['time_range']['to']}\n"
            f"- Data Points: {dp_lines}"
        )
    else:
        cw_metrics_section = "No CloudWatch metric data (alarm may not be a MetricAlarm)."

    # ── Pattern Analysis Section ────────────────────────────────
    p = ctx.patterns
    if p.get("has_history"):
        recurring_flag = "⚠️ YES — treat as CRITICAL recurring issue" if p["is_recurring_issue"] else "NO — first occurrence or isolated event"
        root_cause_list = "\n".join(
            f"  {i+1}. {rc}" for i, rc in enumerate(p["recurring_root_causes"])
        ) or "  (none)"
        pattern_section = (
            f"- Total recorded incidents: {p['total_occurrences']} "
            f"(ALARM events: {p['alarm_occurrences']})\n"
            f"- Last 1 hour: {p['occurrences_last_1h']} occurrence(s)\n"
            f"- Last 24 hours: {p['occurrences_last_24h']} occurrence(s)\n"
            f"- Last 7 days: {p['occurrences_last_7d']} occurrence(s)\n"
            f"- Is recurring issue: {recurring_flag}\n"
            f"- Last occurrence: {p['last_occurrence_time']} (state: {p['last_occurrence_state']})\n"
            f"- Recent state pattern: {p['recent_state_pattern']}\n"
            f"- Recurring root causes across past events:\n{root_cause_list}"
        )
    else:
        pattern_section = "No previous history — this may be the first occurrence."

    # ── Previous Event Details Section ──────────────────────────
    if ctx.history:
        detail_lines = []
        for h in ctx.history:
            detail_lines.append(
                f"[{h['timestamp']}] {h['new_state']} ({h['old_state']} → {h['new_state']})\n"
                f"  Alarm: {h['alarm_name']}\n"
                f"  Summary: {h['summary']}\n"
                f"  Root Cause: {h['root_cause']}\n"
                f"  Recommendations: {h['recommendations'][:120]}..."
            )
        event_details_section = "\n\n".join(detail_lines)
    else:
        event_details_section = "No previous event details available."

    return (
        f"## CloudWatch Alarm\n"
        f"- Alarm Name: {alarm.alarm_name}\n"
        f"- State Change: {alarm.old_state} → {alarm.new_state}\n"
        f"- Service: {alarm.service_name} / Region: {alarm.region}\n"
        f"- Trigger: {alarm.trigger_str}\n"
        f"- Description: {alarm.alarm_description}\n"
        f"- Occurred: {alarm.state_change_time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        f"## Grafana Metrics\n{grafana_section}\n\n"
        f"## CloudWatch Actual Metrics (±{window_minutes} min)\n{cw_metrics_section}\n\n"
        f"## CloudWatch Application Logs (±{window_minutes} min)\n{logs_section}\n\n"
        f"## Incident Pattern Analysis for '{alarm.service_name}'\n{pattern_section}\n\n"
        f"## Previous Event Details for '{alarm.service_name}'\n{event_details_section}"
    )


# ─────────────────────────────────────────────
# LangChain LCEL 파이프라인
# ─────────────────────────────────────────────

class AnalysisPipeline:
    """
    LangChain LCEL 파이프라인:

    AlarmEvent
      → RunnableParallel         # Grafana + CWLogs 병렬 수집
      → EnrichedContext          # 컨텍스트 구성
      → ChatPromptTemplate       # 프롬프트 생성
      → ChatAnthropic            # Claude 분석
        .with_structured_output  # AnalysisOutput 타입 보장
      → SlackNotifier            # 결과 전송
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._state_filter = config.alarm_state_filter

        grafana = GrafanaClient(config)
        cw_logs_client = CWLogsClient(config)
        cw_metrics_client = CWMetricsClient(config)
        notifier = SlackNotifier(config)
        memory = AlarmContextMemory(
            config.alarm_memory_path,
            config.alarm_memory_max_records,
        )
        window_minutes = config.cw_log_window_minutes

        # LangChain LLM (structured output)
        llm = ChatAnthropic(
            model_name="claude-sonnet-4-5",
            base_url=config.anthropic_api_url,
            temperature=0,
            max_tokens_to_sample=4096,
            timeout=None,
            stop=None,
            default_headers={
                "Authorization": f"Bearer {config.anthropic_api_key}",
            }
        ).with_structured_output(AnalysisOutput)

        # Step 1: 병렬 데이터 수집
        # Input: AlarmEvent → Output: {"alarm": AlarmEvent, "grafana_data": ..., "cw_logs": ...}
        def _get_grafana(alarm: AlarmEvent) -> Optional[dict]:
            if CWLogsClient._is_ecs_alarm(alarm):
                short_name = cw_logs_client.get_container_name(alarm.service_name)
                container_name = f"Containers {short_name}" if short_name else ""
            else:
                container_name = ""
            return grafana.get_metrics(alarm, container_name=container_name)

        enrich_step = RunnableParallel({
            "alarm":        RunnablePassthrough(),
            "grafana_data": RunnableLambda(_get_grafana),
            "cw_logs":      RunnableLambda(lambda alarm: cw_logs_client.get_logs(alarm)),
            "cw_metrics":   RunnableLambda(lambda alarm: cw_metrics_client.get_metrics(alarm)),
        })

        # history + patterns 조회 (in-memory, I/O 없음)
        def _add_history_and_patterns(d: dict) -> dict:
            alarm_ = d["alarm"]
            return {
                **d,
                "history":  memory.get_related_history(alarm_),
                "patterns": memory.analyze_patterns(alarm_),
            }

        add_history_step = RunnableLambda(_add_history_and_patterns)

        # Step 2: EnrichedContext 구성 (history + patterns 포함)
        # Input: dict → Output: EnrichedContext
        to_context_step = RunnableLambda(
            lambda d: EnrichedContext(
                alarm=d["alarm"],
                grafana_data=d["grafana_data"],
                cw_logs=d["cw_logs"],
                cw_metrics=d["cw_metrics"],
                history=d["history"],
                patterns=d["patterns"],
            )
        )

        # Step 3: Claude 분석 (프롬프트 생성 → LLM → AnalysisOutput)
        # Input: EnrichedContext → Output: {"alarm": AlarmEvent, "result": AnalysisOutput}
        def analyze(ctx: EnrichedContext) -> dict:
            context_text = _build_context_text(ctx, window_minutes)
            result = (_PROMPT_TEMPLATE | llm).invoke({"context": context_text})
            logger.info(f"Claude 분석 완료: {result.summary[:60]}...")
            return {"alarm": ctx.alarm, "result": result}

        analyze_step = RunnableLambda(analyze)

        # Step 4: 이력 저장 + Slack 전송
        def save_and_notify(d: dict) -> None:
            memory.save(d["alarm"], d["result"])
            notifier.send(d["alarm"], d["result"])

        save_and_notify_step = RunnableLambda(save_and_notify)

        # 전체 LCEL 체인
        self._chain = (
            enrich_step
            | add_history_step
            | to_context_step
            | analyze_step
            | save_and_notify_step
        )

    def process(self, alarm: AlarmEvent) -> None:
        # 알람 상태 필터
        if self._state_filter and alarm.new_state not in self._state_filter:
            logger.info(f"상태 필터로 스킵: {alarm.alarm_name} ({alarm.new_state})")
            return

        logger.info(
            f"알람 처리 시작: {alarm.alarm_name} "
            f"({alarm.old_state} → {alarm.new_state}, 서비스: {alarm.service_name})"
        )

        try:
            self._chain.invoke(alarm)
        except Exception as e:
            logger.error(
                f"파이프라인 처리 실패 ({alarm.alarm_name}): {e}", exc_info=True
            )


# ─────────────────────────────────────────────
# Slack Bot 핸들러 (Socket Mode)
# ─────────────────────────────────────────────

class SlackBotHandler:
    """Slack Socket Mode로 모니터링 채널 메시지 실시간 수신."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._web_client = WebClient(token=config.slack_bot_token)
        self._parser = SlackAlarmParser()
        self._bot_user_id: Optional[str] = None

    def _get_bot_user_id(self) -> Optional[str]:
        try:
            resp = self._web_client.auth_test()
            return resp.get("user_id")
        except Exception as e:
            logger.warning(f"Bot user ID 조회 실패: {e}")
            return None

    def start(self, pipeline: AnalysisPipeline) -> None:
        self._bot_user_id = self._get_bot_user_id()
        logger.info(f"Bot 시작 (user_id: {self._bot_user_id})")
        logger.info(f"모니터링 채널: {self._config.slack_monitor_channel_id}")

        socket_client = SocketModeClient(
            app_token=self._config.slack_app_token,
            web_client=self._web_client,
        )

        def handle_event(client, req: SocketModeRequest) -> None:
            # ACK 즉시 응답 (3초 내 응답 필요)
            client.send_socket_mode_response(
                SocketModeResponse(envelope_id=req.envelope_id)
            )

            if req.type != "events_api":
                return

            event = req.payload.get("event", {})
            ev_type = event.get("type", "")
            ev_channel = event.get("channel", "")

            logger.info(f"이벤트 수신: type={ev_type}, channel={ev_channel}")

            if ev_type != "message":
                logger.info(f"  → message 타입 아님, 스킵 (type={ev_type})")
                return

            # 모니터링 채널 필터
            if ev_channel != self._config.slack_monitor_channel_id:
                logger.info(
                    f"  → 채널 불일치, 스킵 "
                    f"(수신={ev_channel}, 설정={self._config.slack_monitor_channel_id})"
                )
                return

            # Bot 자신의 메시지 무시 (무한루프 방지)
            if event.get("user") == self._bot_user_id:
                logger.info("  → Bot 자신의 메시지, 스킵")
                return

            # Slack 메시지 파싱 (AWS SNS 알림 전체 처리)
            alarm = self._parser.parse(event)
            if alarm is None:
                logger.info(f"  → AWS SNS 알림 아님, 스킵: {event.get('text', '')[:60]}")
                return

            logger.info(f"  → 알람 수신: {alarm.alarm_name}")
            pipeline.process(alarm)

        # 시그널 기반 종료 (SIGTERM: systemctl/kill, SIGINT: Ctrl+C)
        stop_event = threading.Event()

        def _on_signal(signum: int, frame) -> None:
            sig_name = signal.Signals(signum).name
            logger.info(f"시그널 수신 ({sig_name}), 종료 준비 중...")
            stop_event.set()

        signal.signal(signal.SIGTERM, _on_signal)
        signal.signal(signal.SIGINT, _on_signal)

        socket_client.socket_mode_request_listeners.append(handle_event)
        socket_client.connect()
        logger.info("Socket Mode 연결 완료. 이벤트 대기 중... (SIGTERM/SIGINT로 종료)")

        stop_event.wait()   # SIGTERM 또는 SIGINT 수신 시까지 블로킹
        logger.info("소켓 연결 종료 중...")
        socket_client.close()
        logger.info("종료 완료")


# ─────────────────────────────────────────────
# Debug 커맨드 (개발/진단용)
# ─────────────────────────────────────────────

def _ok(msg: str):   print(f"  [OK]    {msg}")
def _warn(msg: str): print(f"  [WARN]  {msg}")
def _err(msg: str):  print(f"  [ERROR] {msg}")
def _info(msg: str): print(f"  [INFO]  {msg}")

def _section(title: str):
    print(f"\n{'='*60}\n  {title}\n{'='*60}")


def cmd_check() -> None:
    """토큰/채널/권한 확인 (연결 없이)."""
    _section("check: 토큰 및 채널 확인")

    bot_token  = os.environ.get("SLACK_BOT_TOKEN", "")
    app_token  = os.environ.get("SLACK_APP_TOKEN", "")
    channel_id = os.environ.get("SLACK_MONITOR_CHANNEL_ID", "")

    for key, val, prefix in [
        ("SLACK_BOT_TOKEN",        bot_token,  "xoxb-"),
        ("SLACK_APP_TOKEN",        app_token,  "xapp-"),
        ("SLACK_MONITOR_CHANNEL_ID", channel_id, "C"),
    ]:
        if not val:
            _err(f"{key} 미설정")
        elif val.startswith(prefix):
            _ok(f"{key} 형식 정상")
        else:
            _warn(f"{key} 형식 확인 필요: '{val[:12]}...'")

    if not bot_token:
        return

    client = WebClient(token=bot_token)

    print("\n[Bot 인증]")
    try:
        auth = client.auth_test()
        _ok(f"인증 성공")
        _info(f"Bot 이름  : {auth.get('user')}")
        _info(f"Bot ID    : {auth.get('user_id')}")
        _info(f"워크스페이스: {auth.get('team')}")
        bot_user_id = auth.get("user_id")
    except SlackApiError as e:
        _err(f"인증 실패: {e.response['error']}")
        return

    print(f"\n[채널 확인: {channel_id}]")
    try:
        info = client.conversations_info(channel=channel_id)
        ch = info.get("channel", {})
        _ok("채널 조회 성공")
        _info(f"채널 이름: #{ch.get('name', 'N/A')}")
        _info(f"채널 타입: {'비공개' if ch.get('is_private') else '공개'}")
    except SlackApiError as e:
        _err(f"채널 조회 실패: {e.response['error']}")
        if e.response["error"] == "channel_not_found":
            _warn("채널 ID 확인 또는 Bot 초대 필요: /invite @<봇이름>")
        return

    print(f"\n[Bot 채널 멤버 확인]")
    try:
        cursor, is_member = None, False
        while True:
            kw = {"channel": channel_id, "limit": 200}
            if cursor:
                kw["cursor"] = cursor
            resp = client.conversations_members(**kw)
            if bot_user_id in resp.get("members", []):
                is_member = True
                break
            cursor = resp.get("response_metadata", {}).get("next_cursor")
            if not cursor:
                break
        if is_member:
            _ok("Bot이 채널 멤버로 확인됨")
        else:
            _err("Bot이 채널 멤버 아님 → /invite @<봇이름> 필요")
    except SlackApiError as e:
        _warn(f"멤버 확인 실패: {e.response['error']}")

    print(f"\n[필요 Scope 확인]")
    scopes_raw = auth.headers.get("x-oauth-scopes", "")
    if scopes_raw:
        scopes = set(scopes_raw.split(","))
        for s in ("channels:history", "groups:history", "channels:read"):
            if s in scopes:
                _ok(f"scope 있음: {s}")
            else:
                _warn(f"scope 없음: {s} ← OAuth & Permissions에서 추가 필요")
    else:
        _warn("scope 정보 조회 불가 — Slack App 설정에서 직접 확인하세요")


def cmd_history(limit: int = 5) -> None:
    """채널 최근 메시지 조회 (conversations.history API)."""
    _section(f"history: 최근 {limit}개 메시지 조회")

    bot_token  = os.environ.get("SLACK_BOT_TOKEN", "")
    channel_id = os.environ.get("SLACK_MONITOR_CHANNEL_ID", "")
    if not bot_token or not channel_id:
        _err("SLACK_BOT_TOKEN / SLACK_MONITOR_CHANNEL_ID 환경변수 필요")
        return

    client = WebClient(token=bot_token)
    try:
        resp = client.conversations_history(channel=channel_id, limit=limit)
        messages = resp.get("messages", [])
        _ok(f"{len(messages)}개 메시지 조회 성공")
    except SlackApiError as e:
        _err(f"conversations.history 실패: {e.response['error']}")
        if e.response["error"] == "missing_scope":
            _warn("channels:history 또는 groups:history scope 필요")
        return

    print()
    for i, msg in enumerate(messages, 1):
        ts  = msg.get("ts", "0")
        dt  = datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        text = msg.get("text", "")[:80]
        user = msg.get("user", msg.get("bot_id", "?"))
        has_att = bool(msg.get("attachments"))

        print(f"[{i}] {dt} | user={user} | attachments={has_att}")
        print(f"     text: {repr(text)}")
        if has_att:
            att = msg["attachments"][0]
            print(f"     color: {att.get('color', '-')}")
            for f in att.get("fields", []):
                print(f"     [{f.get('title','?')}]: {str(f.get('value',''))[:50]}")
        print()


def cmd_listen() -> None:
    """Socket Mode 실시간 수신 — 모든 이벤트를 필터 없이 raw 출력."""
    _section("listen: Socket Mode 실시간 이벤트 수신 (Ctrl+C 종료)")

    bot_token  = os.environ.get("SLACK_BOT_TOKEN", "")
    app_token  = os.environ.get("SLACK_APP_TOKEN", "")
    channel_id = os.environ.get("SLACK_MONITOR_CHANNEL_ID", "")
    if not bot_token or not app_token:
        _err("SLACK_BOT_TOKEN / SLACK_APP_TOKEN 환경변수 필요")
        return

    web_client = WebClient(token=bot_token)
    try:
        auth = web_client.auth_test()
        _ok(f"Bot 인증: {auth.get('user')} ({auth.get('user_id')})")
        bot_user_id = auth.get("user_id")
    except SlackApiError as e:
        _err(f"Bot 인증 실패: {e.response['error']}")
        return

    parser = SlackAlarmParser()
    count = [0]

    def handle_all(client, req: SocketModeRequest) -> None:
        client.send_socket_mode_response(SocketModeResponse(envelope_id=req.envelope_id))
        count[0] += 1
        now = datetime.now().strftime("%H:%M:%S")
        print(f"\n{'─'*60}")
        print(f"[#{count[0]}] {now} | type={req.type}")

        if req.type == "events_api":
            event = req.payload.get("event", {})
            ev_ch   = event.get("channel", "?")
            ev_user = event.get("user", event.get("bot_id", "?"))
            ev_text = event.get("text", "")[:60]
            has_att = bool(event.get("attachments"))

            print(f"  type    : {event.get('type','?')}")
            print(f"  channel : {ev_ch}  {'← 모니터링 채널' if ev_ch == channel_id else '← 다른 채널'}")
            print(f"  user    : {ev_user}  {'← 본인' if ev_user == bot_user_id else ''}")
            print(f"  text    : {repr(ev_text)}")
            print(f"  attachments: {has_att}")

            if has_att:
                att = event["attachments"][0]
                print(f"  color: {att.get('color','-')}")
                for f in att.get("fields", []):
                    print(f"  [{f.get('title','?')}]: {str(f.get('value',''))[:50]}")

            alarm = parser.parse(event)
            is_aws = parser.is_aws_notification(event)
            print(f"\n  AWS SNS 알림: {'YES' if is_aws else 'NO'}")
            if is_aws:
                if alarm:
                    print(f"  [파싱 성공] {'CloudWatch' if parser.is_cloudwatch_alarm(event) else '기타 AWS'}")
                    print(f"    alarm_name  : {alarm.alarm_name}")
                    print(f"    service_name: {alarm.service_name}")
                    print(f"    new_state   : {alarm.new_state}")
                    print(f"    region      : {alarm.region}")
                else:
                    print(f"  [파싱 실패] parse() → None")

    stop_event = threading.Event()

    def _on_signal(signum: int, frame) -> None:
        print(f"\n[{signal.Signals(signum).name}] 종료 신호 수신.")
        stop_event.set()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    try:
        socket_client = SocketModeClient(app_token=app_token, web_client=web_client)
        socket_client.socket_mode_request_listeners.append(handle_all)
        socket_client.connect()
        _ok("Socket Mode 연결 성공! 이벤트 대기 중... (SIGTERM/SIGINT로 종료)")
        print("  [TIP] 모니터링 채널에 메시지를 보내면 이벤트가 출력됩니다.\n")
        stop_event.wait()
        socket_client.close()
        print("종료 완료.")
    except Exception as e:
        _err(f"Socket Mode 연결 실패: {e}")
        _warn("SLACK_APP_TOKEN 확인 및 Slack App에서 Socket Mode 활성화 확인")


def cmd_parse(limit: int = 5) -> None:
    """채널 최근 메시지를 SlackAlarmParser로 파싱 테스트."""
    _section(f"parse: 최근 {limit}개 메시지 파싱 테스트")

    bot_token  = os.environ.get("SLACK_BOT_TOKEN", "")
    channel_id = os.environ.get("SLACK_MONITOR_CHANNEL_ID", "")
    if not bot_token or not channel_id:
        _err("SLACK_BOT_TOKEN / SLACK_MONITOR_CHANNEL_ID 환경변수 필요")
        return

    client = WebClient(token=bot_token)
    try:
        resp = client.conversations_history(channel=channel_id, limit=limit)
        messages = resp.get("messages", [])
    except SlackApiError as e:
        _err(f"conversations.history 실패: {e.response['error']}")
        return

    parser = SlackAlarmParser()
    parsed = 0
    for i, msg in enumerate(messages, 1):
        ts   = msg.get("ts", "0")
        dt   = datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        text = msg.get("text", "")[:60]
        print(f"\n[{i}] {dt} | text={repr(text)}")

        alarm = parser.parse(msg)
        if alarm:
            parsed += 1
            _ok("파싱 성공!")
            print(f"     alarm_name  : {alarm.alarm_name}")
            print(f"     service_name: {alarm.service_name}")
            print(f"     new_state   : {alarm.new_state}")
            print(f"     region      : {alarm.region}")
            print(f"     metric_name : {alarm.metric_name}")
        else:
            _info("CloudWatch 알람 아님")

    print(f"\n{'─'*60}")
    print(f"결과: {len(messages)}개 중 {parsed}개 파싱 성공")
    if parsed == 0 and messages:
        _warn("파싱된 알람 없음 — 채널 ID 또는 메시지 형식을 확인하세요.")
        _warn("  → 'history' 커맨드로 실제 메시지 구조를 확인하세요.")


def cmd_test(limit: int = 20) -> None:
    """채널의 기존 알람 메시지를 가져와 전체 파이프라인(Grafana+CWLogs+Claude+Slack) 실행.

    실제 알람 발생을 기다리지 않고 기존 메시지로 end-to-end 테스트.
    """
    _section(f"test: 기존 알람으로 전체 파이프라인 동작 테스트 (최근 {limit}개 조회)")

    bot_token  = os.environ.get("SLACK_BOT_TOKEN", "")
    channel_id = os.environ.get("SLACK_MONITOR_CHANNEL_ID", "")
    if not bot_token or not channel_id:
        _err("SLACK_BOT_TOKEN / SLACK_MONITOR_CHANNEL_ID 환경변수 필요")
        return

    # 1. Slack 채널에서 최근 메시지 조회
    client = WebClient(token=bot_token)
    try:
        resp = client.conversations_history(channel=channel_id, limit=limit)
        messages = resp.get("messages", [])
        _ok(f"{len(messages)}개 메시지 조회")
    except SlackApiError as e:
        _err(f"conversations.history 실패: {e.response['error']}")
        return

    # 2. AWS SNS 알람 메시지 파싱
    parser = SlackAlarmParser()
    alarms = []
    for msg in messages:
        alarm = parser.parse(msg)
        if alarm:
            alarms.append(alarm)

    if not alarms:
        _warn("AWS SNS 알람 메시지를 찾지 못했습니다.")
        _warn("  → 'history' 커맨드로 채널 메시지 형식을 확인하세요.")
        return

    _ok(f"{len(alarms)}개 알람 발견")
    for i, a in enumerate(alarms, 1):
        ts = a.state_change_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"  [{i}] {ts} | {a.new_state:5s} | {a.alarm_name}")

    # 3. 파이프라인 초기화 (1회만)
    try:
        config = Config.from_env()
    except ValueError as e:
        _err(f"환경변수 오류: {e}")
        return

    try:
        pipeline = AnalysisPipeline(config)
    except Exception as e:
        _err(f"파이프라인 초기화 실패: {e}")
        return

    # 4. 발견된 알람 전체를 순서대로 분석 및 Slack 전송
    success, failed = 0, 0
    for i, alarm in enumerate(alarms, 1):
        print(f"\n{'─'*60}")
        print(f"[{i}/{len(alarms)}] 분석 중...")
        print(f"  alarm_name  : {alarm.alarm_name}")
        print(f"  service_name: {alarm.service_name}")
        print(f"  new_state   : {alarm.new_state}")
        print(f"  발생 시각   : {alarm.state_change_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        try:
            pipeline.process(alarm)
            _ok(f"[{i}/{len(alarms)}] 완료 — Slack 전송됨")
            success += 1
        except Exception as e:
            _err(f"[{i}/{len(alarms)}] 실패: {e}")
            failed += 1

    print(f"\n{'='*60}")
    print(f"결과: 총 {len(alarms)}개 중 성공 {success}개 / 실패 {failed}개")


# ─────────────────────────────────────────────
# 진입점
# ─────────────────────────────────────────────

_USAGE = """
사용법:
  python analysis_mon_event.py              # 정상 실행 (분석 파이프라인)
  python analysis_mon_event.py check        # 토큰/채널/권한 확인
  python analysis_mon_event.py history [N]  # 채널 최근 N개 메시지 조회 (기본 5)
  python analysis_mon_event.py listen       # Socket Mode 원시 이벤트 확인
  python analysis_mon_event.py parse [N]    # 최근 N개 메시지 파싱 테스트
  python analysis_mon_event.py test [N]     # 기존 알람으로 전체 파이프라인 테스트
"""


def main() -> None:
    args = sys.argv[1:]

    if not args:
        logger.info("모니터링 이벤트 분석기 시작")

        # 1. 설정 로드
        try:
            config = Config.from_env()
            logger.info("설정 로드 완료")
        except ValueError as e:
            logger.error(f"환경변수 오류: {e}")
            logger.error("→ .env 파일을 확인하거나 'check' 커맨드로 진단하세요.")
            sys.exit(1)

        # 2. 분석 파이프라인 초기화
        try:
            pipeline = AnalysisPipeline(config)
            logger.info("분석 파이프라인 초기화 완료")
        except Exception as e:
            logger.error(f"AnalysisPipeline 초기화 실패: {e}")
            logger.error("→ ANTHROPIC_API_KEY / ANTHROPIC_API_URL 설정을 확인하세요.")
            sys.exit(1)

        # 3. Slack Bot 시작
        try:
            handler = SlackBotHandler(config)
            handler.start(pipeline)
        except Exception as e:
            logger.error(f"SlackBotHandler 시작 실패: {e}")
            logger.error("→ SLACK_BOT_TOKEN / SLACK_APP_TOKEN 설정을 확인하세요.")
            logger.error("→ 'check' 또는 'listen' 커맨드로 Slack 연결을 먼저 진단하세요.")
            sys.exit(1)
        return

    cmd = args[0]
    if cmd == "check":
        cmd_check()
    elif cmd == "history":
        cmd_history(int(args[1]) if len(args) > 1 else 5)
    elif cmd == "listen":
        cmd_listen()
    elif cmd == "parse":
        cmd_parse(int(args[1]) if len(args) > 1 else 5)
    elif cmd == "test":
        cmd_test(int(args[1]) if len(args) > 1 else 20)
    else:
        print(_USAGE)


if __name__ == "__main__":
    main()
