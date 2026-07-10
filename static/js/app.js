const { createApp } = Vue;

const CHART_COLORS = [
    "#4f8cff", "#ff6b6b", "#ffd166", "#06d6a0", "#c77dff",
    "#f77f00", "#2ec4b6", "#e63946", "#8ac926", "#ff9f1c",
];

createApp({
    data() {
        return {
            tab: "main",
            topN: 10,
            meta: {},
            mappingRate: {},
            attackMatrix: [],
            searchQuery: "",
            searchResults: [],
            selectedSample: { sha256_hash: "", yara_matches: [], attack_mapping: [] },
            groups: [],
            selectedGroupTag: "",
            groupChain: {},
            llmAnalysis: null,
            llmLoading: false,
            llmError: "",
            _charts: {},
            _searchTimer: null,
        };
    },
    computed: {
        attackMatrixGrouped() {
            const groups = {};
            for (const row of this.attackMatrix) {
                if (!groups[row.tactic]) groups[row.tactic] = [];
                groups[row.tactic].push(row);
            }
            return Object.entries(groups).map(([tactic, items]) => ({ tactic, items }));
        },
    },
    watch: {
        tab(newTab) {
            this.$nextTick(() => {
                if (newTab === "main") this.loadMainCharts();
                if (newTab === "attack") this.loadAttackTab();
            });
        },
    },
    mounted() {
        this.loadMeta();
        const params = new URLSearchParams(window.location.search);
        const tabParam = params.get("tab");
        const groupParam = params.get("group");
        if (tabParam) this.tab = tabParam;
        if (groupParam) this.selectedGroupTag = groupParam;

        this.$nextTick(() => {
            if (this.tab === "attack") {
                this.loadAttackTab().then(() => {
                    if (this.selectedGroupTag) this.loadGroupChain();
                });
            } else {
                this.loadMainCharts();
            }
        });
    },
    methods: {
        async fetchJSON(url) {
            const res = await fetch(url);
            if (!res.ok) throw new Error(`${url} -> ${res.status}`);
            return res.json();
        },
        async postJSON(url) {
            const res = await fetch(url, { method: "POST" });
            const body = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(body.error || `${url} -> ${res.status}`);
            return body;
        },
        formatDate(value) {
            if (!value) return "-";
            return String(value).slice(0, 10);
        },
        metaFields(sample) {
            const {
                yara_matches, attack_mapping, behaviors, references, live_enriched,
                imphash, tlsh, ssdeep, vendor_family, vendor_score, enriched_at,
                ...rest
            } = sample;
            return rest;
        },
        heatColor(count) {
            const max = Math.max(1, ...this.attackMatrix.map((r) => r.count));
            const ratio = count / max;
            const g = Math.round(140 + ratio * 100);
            return `rgb(${Math.round(80 + ratio * 60)}, ${g}, 255)`;
        },
        renderChart(id, config) {
            const canvas = document.getElementById(id);
            if (!canvas) return;
            if (this._charts[id]) this._charts[id].destroy();
            this._charts[id] = new Chart(canvas, config);
        },
        async loadMeta() {
            try {
                this.meta = await this.fetchJSON("/api/meta");
            } catch (e) {
                console.error(e);
            }
        },
        async loadMainCharts() {
            try {
                const [sigs, series, filetypes, yara, drivers] = await Promise.all([
                    this.fetchJSON(`/api/dashboard/top-signatures?n=${this.topN}`),
                    this.fetchJSON("/api/dashboard/timeseries"),
                    this.fetchJSON("/api/dashboard/filetypes"),
                    this.fetchJSON(`/api/dashboard/top-yara-rules?n=${this.topN}`),
                    this.fetchJSON("/api/drivers/category"),
                ]);

                this.renderChart("chart-signatures", {
                    type: "bar",
                    data: {
                        labels: sigs.map((r) => r.signature),
                        datasets: [{ label: "탐지 수", data: sigs.map((r) => r.count), backgroundColor: CHART_COLORS[0] }],
                    },
                    options: baseOptions(),
                });

                this.renderChart("chart-timeseries", {
                    type: "line",
                    data: {
                        labels: series.map((r) => this.formatDate(r.date)),
                        datasets: [{ label: "일별 탐지 건수", data: series.map((r) => r.count), borderColor: CHART_COLORS[1], tension: 0.3, fill: false }],
                    },
                    options: baseOptions(),
                });

                this.renderChart("chart-filetypes", {
                    type: "doughnut",
                    data: {
                        labels: filetypes.map((r) => r.file_type),
                        datasets: [{ data: filetypes.map((r) => r.count), backgroundColor: CHART_COLORS }],
                    },
                    options: noScaleOptions(),
                });

                this.renderChart("chart-yara", {
                    type: "bar",
                    data: {
                        labels: yara.map((r) => r.rule_name),
                        datasets: [{ label: "매칭 수", data: yara.map((r) => r.count), backgroundColor: CHART_COLORS[2] }],
                    },
                    options: { ...baseOptions(), indexAxis: "y" },
                });

                this.renderChart("chart-drivers", {
                    type: "pie",
                    data: {
                        labels: drivers.map((r) => r.category),
                        datasets: [{ data: drivers.map((r) => r.count), backgroundColor: CHART_COLORS }],
                    },
                    options: noScaleOptions(),
                });
            } catch (e) {
                console.error(e);
            }
        },
        async loadAttackTab() {
            try {
                const [rate, techniques, matrix, groups] = await Promise.all([
                    this.fetchJSON("/api/attack/mapping-rate"),
                    this.fetchJSON(`/api/attack/techniques?n=${this.topN}`),
                    this.fetchJSON("/api/attack/matrix"),
                    this.fetchJSON("/api/attack/groups"),
                ]);
                this.mappingRate = rate;
                this.attackMatrix = matrix;
                this.groups = groups;

                this.renderChart("chart-techniques", {
                    type: "bar",
                    data: {
                        labels: techniques.map((r) => `${r.technique_id}`),
                        datasets: [{ label: "연관 signature 수", data: techniques.map((r) => r.signature_count), backgroundColor: CHART_COLORS[3] }],
                    },
                    options: { ...baseOptions(), indexAxis: "y" },
                });
            } catch (e) {
                console.error(e);
            }
        },
        async loadGroupChain() {
            if (!this.selectedGroupTag) return;
            try {
                this.groupChain = await this.fetchJSON(`/api/attack/group/${encodeURIComponent(this.selectedGroupTag)}`);
            } catch (e) {
                console.error(e);
            }
        },
        onSearch() {
            clearTimeout(this._searchTimer);
            this._searchTimer = setTimeout(async () => {
                if (!this.searchQuery.trim()) {
                    this.searchResults = [];
                    return;
                }
                try {
                    this.searchResults = await this.fetchJSON(`/api/sample/search?q=${encodeURIComponent(this.searchQuery)}`);
                } catch (e) {
                    console.error(e);
                }
            }, 300);
        },
        async loadSample(hash) {
            try {
                this.selectedSample = await this.fetchJSON(`/api/sample/${hash}`);
                this.llmAnalysis = null;
                this.llmError = "";
            } catch (e) {
                console.error(e);
            }
        },
        async runLlmAnalysis() {
            if (!this.selectedSample.sha256_hash || this.llmLoading) return;
            this.llmLoading = true;
            this.llmError = "";
            try {
                const result = await this.postJSON(`/api/sample/${this.selectedSample.sha256_hash}/analyze`);
                // 체크리스트 항목에 화면 전용 체크 상태를 붙인다 (API 응답 스키마에는 없는 필드).
                (result.reversing_checklist || []).forEach((item) => { item.done = false; });
                this.llmAnalysis = result;
            } catch (e) {
                this.llmError = e.message;
            } finally {
                this.llmLoading = false;
            }
        },
        severityBadgeClass(severity) {
            return {
                low: "text-bg-secondary",
                medium: "text-bg-warning",
                high: "text-bg-danger-subtle border border-danger-subtle",
                critical: "text-bg-danger",
            }[severity] || "text-bg-secondary";
        },
        areaLabel(area) {
            return {
                PE_HEADER: "PE 헤더",
                IMPORT_TABLE: "Import Table",
                EXPORT_TABLE: "Export Table",
                STRINGS: "문자열",
                RESOURCES: "리소스",
                ANTI_ANALYSIS: "안티분석/패킹",
                NETWORK: "네트워크",
            }[area] || area;
        },
    },
}).mount("#app");

function baseOptions() {
    return {
        responsive: true,
        plugins: { legend: { labels: { color: "#e6e9f0" } } },
        scales: {
            x: { ticks: { color: "#8a93a8" }, grid: { color: "#2a3550" } },
            y: { ticks: { color: "#8a93a8" }, grid: { color: "#2a3550" } },
        },
    };
}

function noScaleOptions() {
    return {
        responsive: true,
        plugins: { legend: { labels: { color: "#e6e9f0" } } },
    };
}
