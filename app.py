# Page configuration must be the first Streamlit command
import streamlit as st
import urllib3
urllib3.disable_warnings()
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
import os
os.environ['STREAMLIT_SERVER_PORT'] = '8080'
os.environ['STREAMLIT_SERVER_ADDRESS'] = '0.0.0.0'
os.environ['STREAMLIT_SERVER_ENABLECORS'] = 'false'
os.environ['STREAMLIT_SERVER_ENABLEWEBSOCKETCOMPRESSION'] = 'false'

st.set_page_config(
    page_title="SecureAI Guardian", 
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

try:
    import pandas as pd
    import plotly.express as px
    import plotly.graph_objects as go
    from datetime import datetime, timedelta
    import time

    from utils.security_monitor import SecurityMonitor
    from utils.anomaly_detector import AnomalyDetector
    from utils.file_scanner import FileScanner
    from utils.encryption import Encryption
    from utils.alert_manager import AlertManager

    # Initialize components
    @st.cache_resource
    def init_components():
        try:
            return {
                'security_monitor': SecurityMonitor(),
                'anomaly_detector': AnomalyDetector(),
                'file_scanner': FileScanner(),
                'encryption': Encryption(),
                'alert_manager': AlertManager()
            }
        except Exception as e:
            st.error(f"Error initializing components: {str(e)}")
            return None

    components = init_components()

    if not components:
        st.error("Failed to initialize application components. Please try refreshing the page.")
        st.stop()

    # Add custom CSS
    st.markdown("""
        <style>
        .stMetric {
            background-color: #f0f2f6;
            padding: 10px;
            border-radius: 5px;
        }
        </style>
    """, unsafe_allow_html=True)

    # Title and description
    st.title("🛡️ SecureAI Guardian Dashboard")
    st.markdown("""
        Welcome to SecureAI Guardian - Your Real-time Security Monitoring Solution
        * Monitor system metrics and network activity
        * Detect anomalies and potential security threats
        * Scan files for sensitive data
        * Encrypt sensitive files
    """)

    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.radio(
        "Select Page",
        ["Dashboard", "File Scanner", "Encryption", "Alerts"]
    )

    # Dashboard page
    if page == "Dashboard":
        try:
            # System metrics in columns
            col1, col2, col3 = st.columns(3)

            metrics = components['security_monitor'].get_system_metrics()

            with col1:
                st.metric(
                    "CPU Usage",
                    f"{metrics['cpu_percent']}%",
                    delta=None,
                    help="Current CPU utilization"
                )
            with col2:
                st.metric(
                    "Memory Usage",
                    f"{metrics['memory_percent']}%",
                    delta=None,
                    help="Current memory utilization"
                )
            with col3:
                st.metric(
                    "Disk Usage",
                    f"{metrics['disk_usage']}%",
                    delta=None,
                    help="Current disk space utilization"
                )

            # Network Activity
            st.subheader("Network Activity")
            with st.spinner("Loading network statistics..."):
                try:
                    stats = components['security_monitor'].get_network_stats()
                    historical_data = components['security_monitor'].get_historical_data()

                    if historical_data is None or historical_data.empty:
                        st.warning("No network activity data available yet. Please wait a few moments...")
                    elif not isinstance(historical_data, pd.DataFrame):
                        historical_data = pd.DataFrame(historical_data)
                    fig = px.line(
                        historical_data,
                        x='timestamp',
                        y=['bytes_sent', 'bytes_recv'],
                        title='Network Traffic Over Time'
                    )
                    st.plotly_chart(fig, use_container_width=True)

                    # Anomaly detection
                    if len(historical_data) > 10:
                        with st.spinner("Detecting anomalies..."):
                            components['anomaly_detector'].train(historical_data)
                            anomalies = components['anomaly_detector'].detect_anomalies(historical_data)
                            scores = components['anomaly_detector'].get_anomaly_scores(historical_data)

                            if any(anomalies):
                                st.warning("⚠️ Network Traffic Anomalies Detected")

                                # Create anomaly details
                                anomaly_data = historical_data[anomalies].copy()
                                anomaly_data['anomaly_score'] = scores[anomalies]

                                with st.expander("View Anomaly Details"):
                                    st.markdown("""
                                    ### Network Traffic Anomalies
                                    Anomalies are detected based on unusual patterns in:
                                    - Bytes sent/received
                                    - Packet counts
                                    - Traffic patterns
                                    """)

                                    # Show anomalous data points
                                    st.dataframe({
                                        'Timestamp': anomaly_data['timestamp'],
                                        'Bytes Sent': anomaly_data['bytes_sent'],
                                        'Bytes Received': anomaly_data['bytes_recv'],
                                        'Anomaly Score': anomaly_data['anomaly_score'].round(3)
                                    })

                                    # Visualize anomalies
                                    fig = px.scatter(
                                        historical_data,
                                        x='timestamp',
                                        y=['bytes_sent', 'bytes_recv'],
                                        title='Network Traffic with Anomalies Highlighted'
                                    )

                                    # Add anomaly points
                                    fig.add_scatter(
                                        x=anomaly_data['timestamp'],
                                        y=anomaly_data['bytes_sent'],
                                        mode='markers',
                                        marker=dict(color='red', size=10),
                                        name='Anomalies (Bytes Sent)'
                                    )

                                    fig.add_scatter(
                                        x=anomaly_data['timestamp'],
                                        y=anomaly_data['bytes_recv'],
                                        mode='markers',
                                        marker=dict(color='red', size=10),
                                        name='Anomalies (Bytes Received)'
                                    )

                                    st.plotly_chart(fig, use_container_width=True)

                                    # Add explanation of the anomaly scores
                                    st.info("""
                                    **Understanding Anomaly Scores:**
                                    - Higher scores indicate more unusual network behavior
                                    - Scores above 0.8 are considered highly anomalous
                                    - Normal network traffic typically has scores below 0.5
                                    """)

                                components['alert_manager'].add_alert(
                                    f"Network anomaly detected: {len(anomaly_data)} suspicious traffic patterns found",
                                    "HIGH",
                                    "Anomaly Detector"
                                )
                except Exception as e:
                    st.error(f"Error loading network statistics: {str(e)}")

            # Packet Inspection Analysis
            st.subheader("Deep Packet Inspection")
            packet_analysis = components['security_monitor'].get_packet_analysis()

            if packet_analysis['statistics']['packets_analyzed'] == 0:
                st.info("Deep packet inspection is currently disabled. This feature requires elevated privileges.")
            else:
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric(
                        "Packets Analyzed",
                        packet_analysis['statistics']['packets_analyzed'],
                        help="Total number of packets analyzed"
                    )

                # Protocol Distribution Chart
                if packet_analysis['statistics']['protocol_distribution']:
                    protocol_data = pd.DataFrame({
                        'Protocol': list(packet_analysis['statistics']['protocol_distribution'].keys()),
                        'Count': list(packet_analysis['statistics']['protocol_distribution'].values())
                    })
                    fig_protocol = px.pie(
                        protocol_data,
                        values='Count',
                        names='Protocol',
                        title='Protocol Distribution'
                    )
                    st.plotly_chart(fig_protocol, use_container_width=True)

                # Display other packet analysis visualizations...
                if packet_analysis['threats']:
                    st.subheader("⚠️ Security Threats Detected")
                    for threat in packet_analysis['threats']:
                        with st.expander(f"{threat['type']} (Severity: {threat['severity']})"):
                            st.write(threat['details'])
                            if threat['severity'] in ['HIGH', 'CRITICAL']:
                                components['alert_manager'].add_alert(
                                    threat['details'],
                                    threat['severity'],
                                    "Packet Inspector"
                                )

        except Exception as e:
            st.error(f"Error in Dashboard: {str(e)}")

    elif page == "File Scanner":
        try:
            st.subheader("Sensitive Data Scanner")
            uploaded_file = st.file_uploader(
                "Upload a file to scan",
                type=['txt', 'csv', 'log'],
                help="Select a file to scan for sensitive information"
            )

            if uploaded_file:
                with st.spinner("Scanning file..."):
                    # Save temporary file
                    with open("temp_file", "wb") as f:
                        f.write(uploaded_file.getvalue())

                    # Scan file
                    results = components['file_scanner'].scan_file("temp_file")

                    # Display results
                    if results.get('patterns'):
                        st.subheader("Pattern Matches")
                        for pattern_name, findings in results['patterns'].items():
                            if findings:
                                st.warning(f"Found {len(findings)} {pattern_name} instances")
                                components['alert_manager'].add_alert(
                                    f"Sensitive data ({pattern_name}) found in uploaded file",
                                    "MEDIUM",
                                    "File Scanner"
                                )

                    if results.get('entities'):
                        st.subheader("Named Entities (AI-Powered Detection)")
                        for entity_type, entities in results['entities'].items():
                            if entities:
                                with st.expander(f"{entity_type} ({len(entities)} found)"):
                                    for entity in entities:
                                        st.markdown(f"""
                                            - **Word:** {entity['word']}
                                            - **Confidence:** {entity['score']*100:.1f}%
                                            ---
                                        """)

        except Exception as e:
            st.error(f"Error in File Scanner: {str(e)}")

    elif page == "Encryption":
        try:
            st.subheader("Sensitive Data Encryption")

            # File upload
            uploaded_file = st.file_uploader(
                "Upload a file to process",
                type=['txt', 'csv', 'log'],
                help="Select a file to scan and encrypt sensitive data"
            )

            if uploaded_file:
                with st.spinner("Processing file..."):
                    # Save uploaded file
                    with open("temp_file", "wb") as f:
                        f.write(uploaded_file.getvalue())

                    # Scan file first
                    scan_results = components['file_scanner'].scan_file("temp_file")

                    if any(scan_results['patterns'].values()):
                        st.warning("Sensitive data found in file:")
                        for pattern, matches in scan_results['patterns'].items():
                            if matches:
                                st.write(f"- {pattern}: {len(matches)} instances found")

                        if st.button("Encrypt Sensitive Data"):
                            try:
                                protected_file, key_file = components['encryption'].encrypt_sensitive_data("temp_file")

                                # Offer downloads
                                with open(protected_file, "r") as f:
                                    st.download_button(
                                        "Download Protected File",
                                        f,
                                        file_name=f"{uploaded_file.name}.protected"
                                    )

                                with open(key_file, "r") as f:
                                    st.download_button(
                                        "Download Decryption Key",
                                        f,
                                        file_name=f"{uploaded_file.name}.key"
                                    )

                                st.success("Sensitive data encrypted successfully!")

                            except Exception as e:
                                st.error(f"Encryption failed: {str(e)}")

                    else:
                        st.success("No sensitive data found in file")

            # Decryption section
            st.subheader("Decrypt Protected File")
            protected_file = st.file_uploader(
                "Upload protected file",
                type=['protected'],
                key="protected_upload"
            )
            key_file = st.file_uploader(
                "Upload key file",
                type=['key'],
                key="key_upload"
            )

            if protected_file and key_file:
                if st.button("Decrypt File"):
                    try:
                        # Save uploaded files
                        with open("temp_protected", "wb") as f:
                            f.write(protected_file.getvalue())
                        with open("temp_key", "wb") as f:
                            f.write(key_file.getvalue())

                        # Decrypt
                        decrypted_file = components['encryption'].decrypt_sensitive_data(
                            "temp_protected",
                            "temp_key"
                        )

                        with open(decrypted_file, "r") as f:
                            st.download_button(
                                "Download Decrypted File",
                                f,
                                file_name=f"{protected_file.name.replace('.protected', '.decrypted')}"
                            )

                        st.success("File decrypted successfully!")

                    except Exception as e:
                        st.error(f"Decryption failed: {str(e)}")

        except Exception as e:
            st.error(f"Error in Encryption: {str(e)}")

    elif page == "Alerts":
        try:
            st.subheader("Security Alerts")
            summary = components['alert_manager'].get_alert_summary()

            fig = go.Figure(data=[
                go.Bar(
                    x=list(summary.keys()),
                    y=list(summary.values()),
                    marker_color=['green', 'yellow', 'orange', 'red']
                )
            ])
            fig.update_layout(
                title="Alerts by Severity",
                xaxis_title="Severity Level",
                yaxis_title="Number of Alerts"
            )
            st.plotly_chart(fig, use_container_width=True)

            active_alerts = components['alert_manager'].get_active_alerts()
            if active_alerts:
                st.warning(f"{len(active_alerts)} Active Alerts")
                for i, alert in enumerate(active_alerts):
                    with st.expander(f"{alert['level']} - {alert['message']}"):
                        st.write(f"Source: {alert['source']}")
                        st.write(f"Time: {alert['timestamp']}")
                        if st.button(f"Mark as Read", key=f"alert_{i}"):
                            components['alert_manager'].mark_alert_as_read(i)
            else:
                st.success("No active alerts")

        except Exception as e:
            st.error(f"Error in Alerts: {str(e)}")

    # Auto-refresh for Dashboard
    if page == "Dashboard":
        time.sleep(5)
        st.rerun()

except Exception as e:
    st.error(f"Application Error: {str(e)}")
    st.error("Please refresh the page or contact support if the issue persists.")