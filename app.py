from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import re
import sqlite3

import pandas as pd
import streamlit as st

st.set_page_config(page_title="AI 智慧防詐分析系統", layout="wide")

DB_PATH = Path("audit_logs.db")

URGENT_KEYWORDS = ["立即", "馬上", "逾期", "最後通知", "停用", "凍結", "限時", "緊急"]
VERIFY_KEYWORDS = ["驗證", "確認帳戶", "重新登入", "輸入密碼", "核對資料", "身分認證"]
INDUCEMENT_KEYWORDS = ["點擊連結", "不明連結", "匯款", "轉帳", "退稅", "中獎", "補助", "優惠"]

SAMPLES = {
    "高風險範例：假冒銀行帳戶異常": (
        "簡訊",
        "【銀行通知】您的帳戶因安全問題暫停使用，請立即點擊以下連結 https://example-verify.test/login 重新驗證帳戶，逾期將停止服務。",
    ),
    "中風險範例：包裹配送通知": (
        "簡訊",
        "【物流提醒】您的包裹因地址資訊待確認，請儘速核對資料或點擊 https://track-sample.test 查詢。",
    ),
    "低風險範例：一般正常提醒": (
        "電子郵件",
        "您好，提醒您本週五下午兩點有線上課程說明會，歡迎準時參加，祝您順心。",
    ),
}


@dataclass
class AnalysisResult:
    masked_text: str
    risk_score: int
    risk_level: str
    triggered_features: list[str]
    fraud_type: str
    explanation: str
    advice: str
    model_version: str = "rule-baseline-v1.0"


def mask_sensitive_info(text: str) -> str:
    masked = text
    masked = re.sub(r"\b09\d{2}[-\s]?\d{3}[-\s]?\d{3}\b", "[PHONE_MASKED]", masked)
    masked = re.sub(r"\b[A-Z][12]\d{8}\b", "[ID_MASKED]", masked)
    masked = re.sub(r"\b\d{6,}\b", "[NUM_MASKED]", masked)
    masked = re.sub(r"https?://[^\s]+", "[URL_DETECTED]", masked)
    return masked


def analyze_message(raw_text: str, channel: str = "簡訊") -> AnalysisResult:
    masked_text = mask_sensitive_info(raw_text.strip())
    features: list[str] = []
    score = 10

    if any(k in masked_text for k in URGENT_KEYWORDS):
        features.append("緊急性用語（製造時間／停用壓力）")
        score += 25

    if any(k in masked_text for k in VERIFY_KEYWORDS):
        features.append("要求帳戶／身分驗證")
        score += 30

    if "[URL_DETECTED]" in masked_text:
        features.append("包含外部連結")
        score += 20

    if any(k in masked_text for k in INDUCEMENT_KEYWORDS):
        features.append("金錢／獎勵／點擊誘導用語")
        score += 20

    score = min(score, 100)

    if score >= 70:
        risk_level = "高風險"
        fraud_type = "疑似釣魚／假冒通知詐騙"
        explanation = (
            f"此則{channel}觸發多項高風險特徵（{'、'.join(features)}），"
            "常見於假冒銀行、物流或政府機關誘導點擊連結或驗證帳戶的情境。"
        )
        advice = (
            "請勿直接點擊訊息內連結，也不要輸入帳號、密碼或個資；"
            "建議透過官方 App、官網或 165 反詐騙專線另行查證。"
        )
    elif score >= 40:
        risk_level = "中風險"
        fraud_type = "可疑通知／待查證訊息"
        explanation = (
            f"此則{channel}出現部分可疑訊號（{'、'.join(features) if features else '語意需進一步留意'}），"
            "建議提高警覺並核實發訊來源。"
        )
        advice = "請勿倉促依指示操作或轉帳，先透過官方管道確認通知是否屬實。"
    else:
        risk_level = "低風險"
        fraud_type = "一般／低風險訊息"
        explanation = "目前未偵測到明顯的緊急施壓、驗證要求或高風險誘導特徵。"
        advice = "仍建議保持良好資安習慣，遇到涉及金錢或帳密變更時多方確認。"

    return AnalysisResult(
        masked_text=masked_text,
        risk_score=score,
        risk_level=risk_level,
        triggered_features=features if features else ["無明顯高風險特徵"],
        fraud_type=fraud_type,
        explanation=explanation,
        advice=advice,
    )


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                audit_id TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL,
                channel TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                fraud_type TEXT NOT NULL,
                triggered_features TEXT NOT NULL,
                summary_advice TEXT NOT NULL,
                model_version TEXT NOT NULL
            )
            """
        )
        conn.commit()


def save_audit_record(
    channel: str,
    risk_score: int,
    risk_level: str,
    fraud_type: str,
    triggered_features: list[str],
    advice: str,
    model_version: str,
) -> str:
    init_db()
    now = datetime.now()
    audit_id = f"AUD-{now.strftime('%Y%m%d-%H%M%S-%f')[:21]}"
    created_at = now.strftime("%Y-%m-%d %H:%M:%S")

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO audit_records (
                audit_id, created_at, channel, risk_score, risk_level,
                fraud_type, triggered_features, summary_advice, model_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit_id,
                created_at,
                channel,
                risk_score,
                risk_level,
                fraud_type,
                json.dumps(triggered_features, ensure_ascii=False),
                advice,
                model_version,
            ),
        )
        conn.commit()
    return audit_id


def fetch_audit_records() -> list[dict]:
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM audit_records ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


init_db()

if "msg_input" not in st.session_state:
    st.session_state.msg_input = SAMPLES["高風險範例：假冒銀行帳戶異常"][1]
if "channel_input" not in st.session_state:
    st.session_state.channel_input = SAMPLES["高風險範例：假冒銀行帳戶異常"][0]

st.title("AI 智慧防詐分析系統")
st.caption("自然語言處理・風險評估・去識別化稽核紀錄（資料最小化原則：不留存原始訊息與敏感個資明文）")

tab1, tab2 = st.tabs(["🔍 訊息防詐分析", "📋 歷史稽核紀錄"])

with tab1:
    st.subheader("1. 選擇測試範例或輸入待分析訊息")

    sample_cols = st.columns(len(SAMPLES))
    for idx, (label, (ch, txt)) in enumerate(SAMPLES.items()):
        if sample_cols[idx].button(label, use_container_width=True):
            st.session_state.channel_input = ch
            st.session_state.msg_input = txt
            st.rerun()

    col_left, col_right = st.columns([1.1, 1])

    with col_left:
        channel = st.selectbox(
            "訊息通道",
            ["簡訊", "電子郵件", "社群平台"],
            index=["簡訊", "電子郵件", "社群平台"].index(st.session_state.channel_input),
        )
        user_msg = st.text_area(
            "請貼上可疑訊息內容",
            value=st.session_state.msg_input,
            height=150,
            placeholder="請輸入簡訊、電子郵件或社群訊息...",
        )
        analyze_btn = st.button("開始分析", type="primary", use_container_width=True)

    with col_right:
        st.subheader("2. 風險評估與分析報告")
        if analyze_btn:
            if not user_msg.strip():
                st.warning("請先輸入訊息內容再進行分析。")
            else:
                result = analyze_message(user_msg, channel=channel)
                audit_id = save_audit_record(
                    channel=channel,
                    risk_score=result.risk_score,
                    risk_level=result.risk_level,
                    fraud_type=result.fraud_type,
                    triggered_features=result.triggered_features,
                    advice=result.advice,
                    model_version=result.model_version,
                )

                m1, m2, m3 = st.columns(3)
                m1.metric("綜合風險分數", f"{result.risk_score} / 100")
                m2.metric("風險等級", result.risk_level)
                m3.metric("模型版本", result.model_version)

                st.progress(result.risk_score / 100)
                st.info(f"**潛在類型：** {result.fraud_type}")

                st.markdown("**辨識出的可疑特徵：**")
                for feat in result.triggered_features:
                    st.write(f"- {feat}")

                st.markdown("**分析說明：**")
                st.write(result.explanation)

                st.markdown("**防詐建議：**")
                st.success(result.advice)

                st.caption(f"已寫入去識別化稽核紀錄｜編號：`{audit_id}`（未儲存原始訊息明文）")

                with st.expander("查看記憶體內去敏處理後文字（僅供除錯檢視）"):
                    st.code(result.masked_text)

with tab2:
    st.subheader("歷史稽核紀錄（去識別化留存）")
    records = fetch_audit_records()
    if not records:
        st.info("目前尚無分析紀錄，請先至「訊息防詐分析」分頁執行分析。")
    else:
        df = pd.DataFrame(records)
        level_filter = st.multiselect(
            "篩選風險等級",
            options=["高風險", "中風險", "低風險"],
            default=["高風險", "中風險", "低風險"],
        )
        filtered_df = df[df["risk_level"].isin(level_filter)] if level_filter else df
        st.dataframe(filtered_df, use_container_width=True, hide_index=True)

        csv_data = filtered_df.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            label="匯出稽核紀錄 CSV",
            data=csv_data,
            file_name="audit_records.csv",
            mime="text/csv",
        )
