import streamlit as st
import json

def create_animation_section(steps_list, entities_list, code=None):
    """
    Creates a dynamic attack animation section with fading effects using diagram data.
    Highlights specific entities involved in each phase.
    Guarantees that all steps belonging to the exact same phase share the identical color using a strict indexed palette.
    Dynamically themes step badges, borders, and flow indicators based on the active phase color.
    Adapts perfectly to Streamlit's Light/Dark mode using CSS variables.
    Includes a dynamic playback speed slider control.
    """
    # Safeguard: Parse inputs if they arrive as raw JSON strings
    if isinstance(entities_list, str):
        try:
            entities_list = json.loads(entities_list)
        except json.JSONDecodeError:
            entities_list = []

    if isinstance(steps_list, str):
        try:
            steps_list = json.loads(steps_list)
        except json.JSONDecodeError:
            steps_list = []

    # Map all unique available entity names for the visual grid layout
    all_entities_list = []
    if isinstance(entities_list, list):
        for entity in entities_list:
            if isinstance(entity, dict):
                ent_name = entity.get('ENTITY') or entity.get('name') or entity.get('id')
                if ent_name and ent_name not in all_entities_list:
                    all_entities_list.append(ent_name)

    # Process and group attack steps sequentially by their designated Phase
    phases_dict = {}
    if isinstance(steps_list, list):
        for step in steps_list:
            if not isinstance(step, dict):
                continue
                
            # SAFE FIX: Safely extract the part after the first colon, handling missing colons gracefully
            raw_phase = step.get('PHASE') or step.get('phase') or 'General Phase'
            phase_name = raw_phase.split(':', 1)[1].strip() if ':' in raw_phase else raw_phase.strip()
            phase_num = step.get('PHASE_NUMBER') or step.get('phase_number', 1)
            
            # Map standard network vector attributes
            source_name = step.get('FROM') or step.get('source')
            target_name = step.get('TO') or step.get('target')
            
            # Build current sequential step structural data payload
            step_data = {
                "num": step.get('STEP') or step.get('number') or step.get('id', ''),
                "title": step.get('TYPE', 'ACTIVITY') or 'Step Details',
                "desc": step.get('DESCRIPTION') or step.get('description', ''),
                "source": source_name,
                "target": target_name,
                "insight": step.get('INSIGHT') or step.get('insight', '')
            }
            
            # Combine under a standardized descriptive phase key string
            phase_key = f"Phase {phase_num}: {phase_name}"
            if phase_key not in phases_dict:
                phases_dict[phase_key] = {
                    "phase": phase_key,
                    "steps": [],
                    "involved_entities": set()
                }
            
            phases_dict[phase_key]["steps"].append(step_data)
            if source_name: 
                phases_dict[phase_key]["involved_entities"].add(source_name)
            if target_name: 
                phases_dict[phase_key]["involved_entities"].add(target_name)

    # Fallback structure if steps execution data extraction loop yielded empty
    if not phases_dict and all_entities_list:
        phases_dict["Attack Overview"] = {
            "phase": "Attack Overview",
            "steps": [{
                "num": "i",
                "title": "SYSTEM READY",
                "desc": "The underlying components are initialized. Advance to start animation.",
                "source": None,
                "target": None,
                "insight": ""
            }],
            "involved_entities": set(all_entities_list)
        }

    # Transform internal set types into list wrappers for standard JSON encoding compliance
    attack_data = []
    for p_name, p_info in phases_dict.items():
        p_info["involved_entities"] = list(p_info["involved_entities"])
        attack_data.append(p_info)

    # Convert the processed structures into safe dynamic JSON strings for JS client handling
    attack_json = json.dumps(attack_data, ensure_ascii=False)
    all_entities_json = json.dumps(all_entities_list, ensure_ascii=False)

    # Dynamic interactive injection markup block utilizing styling and vanilla transitions
    animation_html = f"""
    <div id="animation-container" style="
        font-family: system-ui, -apple-system, sans-serif;
        background-color: var(--background-color, #0e1117);
        color: var(--text-color, #ffffff);
        padding: 20px;
        border-radius: 12px;
        border: 1px solid var(--secondary-background-color, #30363d);
        max-width: 800px;
        margin: 0 auto;
        direction: ltr;
    ">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
            <h2 id="phase-title" style="margin: 0; font-size: 1.3rem; transition: color 0.5s ease, opacity 0.4s ease;"></h2>
            <span id="progress-indicator" style="background-color: var(--secondary-background-color, #21262d); padding: 4px 10px; border-radius: 20px; font-size: 0.85rem; opacity: 0.8;"></span>
        </div>
        
        <div style="margin-bottom: 20px; background: var(--secondary-background-color, #161b22); padding: 15px; border-radius: 8px; border: 1px solid var(--secondary-background-color, #21262d);">
            <span style="font-size: 0.85rem; opacity: 0.7; display: block; margin-bottom: 12px;">Architecture Components Map (Highlighted nodes are active in this phase):</span>
            <div id="architecture-map" style="display: flex; gap: 12px; flex-wrap: wrap; justify-content: center; align-items: center;">
                </div>
        </div>
        
        <div style="width: 100%; height: 6px; background-color: var(--secondary-background-color, #21262d); border-radius: 3px; margin-bottom: 20px; overflow: hidden;">
            <div id="progress-bar" style="width: 0%; height: 100%; transition: width 0.4s ease, background 0.5s ease;"></div>
        </div>

        <div id="step-box" style="
            background: var(--background-color, #1c2128);
            border-left: 4px solid #ff4b4b;
            padding: 15px;
            border-radius: 4px 8px 8px 4px;
            opacity: 0;
            transform: translateY(10px);
            border-top: 1px solid var(--secondary-background-color, #30363d);
            border-right: 1px solid var(--secondary-background-color, #30363d);
            border-bottom: 1px solid var(--secondary-background-color, #30363d);
            transition: opacity 0.5s ease, transform 0.5s ease, border-left-color 0.5s ease;
        ">
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 10px;">
                <span id="step-number" style="
                    background-color: #ff4b4b;
                    color: white;
                    padding: 4px 12px;
                    border-radius: 20px;
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;
                    font-weight: bold;
                    font-size: 0.85rem;
                    transition: background-color 0.5s ease;
                "></span>
                <img id="step-type-icon" src="" style="width: 24px; height: 24px; display: none;" alt="Activity Icon"/>
                <h4 id="step-title" style="margin: 0; font-size: 1.1rem; text-transform: uppercase; letter-spacing: 0.5px;"></h4>
            </div>
            <p id="step-desc" style="margin: 0; font-size: 0.95rem; line-height: 1.5; margin-bottom: 10px; text-align: justify; opacity: 0.9;"></p>
            
            <div id="insight-container" style="margin-top: 8px; margin-bottom: 10px; font-size: 0.9rem; color: #ffb454; background: rgba(255,180,84,0.1); padding: 8px 12px; border-left: 3px solid #ffb454; border-radius: 0 4px 4px 0; display: none;">
                💡 <span id="step-insight"></span>
            </div>

            <div id="flow-badge-container" style="
                font-size: 0.85rem; 
                display: flex; 
                gap: 8px; 
                align-items: center; 
                padding: 6px 12px; 
                border-radius: 4px; 
                width: fit-content;
                transition: background-color 0.5s ease, color 0.5s ease;
            ">
                <span id="step-flow"></span>
            </div>
        </div>

        <div style="display: flex; gap: 15px; margin-top: 20px; justify-content: space-between; align-items: center; flex-wrap: wrap;">
            
            <div style="display: flex; align-items: center; gap: 10px; background: var(--secondary-background-color, #161b22); padding: 6px 14px; border-radius: 8px; border: 1px solid var(--secondary-background-color, #30363d);">
                <label for="speed-slider" style="font-size: 0.8rem; font-weight: 500; opacity: 0.8; white-space: nowrap;">Speed:</label>
                <input type="range" id="speed-slider" min="1" max="5" value="1" oninput="updateSpeed(this.value)" style="cursor: pointer; width: 90px; accent-color: #ff4b4b;">
                <span id="speed-label" style="font-size: 0.8rem; font-weight: bold; min-width: 25px; text-align: right;">1x</span>
            </div>

            <div style="display: flex; gap: 10px; align-items: center;">
                <button id="btn-prev" onclick="prevStep()" style="background: var(--secondary-background-color, #21262d); color: var(--text-color, #c9d1d9); border: 1px solid var(--secondary-background-color, #30363d); padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 500; transition: background 0.2s;">Previous</button>
                
                <div style="display: flex; gap: 5px; background: var(--secondary-background-color, #161b22); padding: 4px; border-radius: 8px; border: 1px solid var(--secondary-background-color, #30363d);">
                    <button id="btn-play" onclick="startPlay()" style="background: transparent; color: var(--text-color, #8b949e); border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-weight: bold; opacity: 0.6; transition: all 0.2s;">Play</button>
                    <button id="btn-pause" onclick="pausePlay()" style="background: #ff4b4b; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-weight: bold; transition: all 0.2s;">Pause</button>
                    <button id="btn-restart" onclick="restartPlay()" style="background: transparent; color: var(--text-color, #8b949e); border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-weight: bold; opacity: 0.6; transition: all 0.2s;">Restart</button>
                </div>

                <button id="btn-next" onclick="nextStep()" style="background: var(--secondary-background-color, #21262d); color: var(--text-color, #c9d1d9); border: 1px solid var(--secondary-background-color, #30363d); padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 500; transition: background 0.2s;">Next</button>
            </div>
        </div>
    </div>

    <script>
        const attackData = {attack_json};
        const allEntities = {all_entities_json};
        
        const iconsMap = {{
            "attacker": "https://img.icons8.com/color/96/evil.png",
            "victim": "https://img.icons8.com/color/96/laptop.png",
            "client": "https://img.icons8.com/color/96/laptop.png",
            "resolver": "https://img.icons8.com/color/96/router.png",
            "authoritative": "https://img.icons8.com/color/96/server.png",
            "non-responsive": "https://img.icons8.com/color/96/server--v2.png",
            "query": "https://img.icons8.com/color/96/ask-question.png",
            "receive": "https://img.icons8.com/color/96/giving.png",
            "cache": "https://img.icons8.com/color/96/database.png",
            "attack": "https://img.icons8.com/?id=zD-VLZTPKlpb",
            "flood": "https://img.icons8.com/?id=zD-VLZTPKlpb",
            "timeout": "https://img.icons8.com/color/96/clock.png",
            "referral": "https://img.icons8.com/color/96/shuffle.png",
            "error": "https://img.icons8.com/color/96/error.png",
            "loop": "https://img.icons8.com/color/96/recurring-appointment.png"
        }};

        // Absolute deterministic palette mapped directly to phase groupings
        const phaseColorsPalette = [
            "hsl(210, 85%, 55%)", // Slate Blue
            "hsl(140, 75%, 45%)", // Emerald Green
            "hsl(35, 95%, 50%)",  // Cyber Amber
            "hsl(280, 75%, 60%)", // Purple
            "hsl(180, 70%, 45%)", // Teal
            "hsl(0, 85%, 55%)"    // Crimson Red
        ];

        // Derived function to generate safe transparent hex equivalents for CSS backgrounds
        function getTransparentColor(hslString, opacity) {{
            return hslString.replace(")", `, ${{opacity}})`).replace("hsl", "hsla");
        }}

        function getEntityIcon(name) {{
            const lowerName = name.toLowerCase();
            if (lowerName.includes("attacker")) return iconsMap["attacker"];
            if (lowerName.includes("non-responsive") || lowerName.includes("non‑responsive")) return iconsMap["non-responsive"];
            if (lowerName.includes("resolver")) return iconsMap["resolver"];
            if (lowerName.includes("authoritative")) return iconsMap["authoritative"];
            if (lowerName.includes("victim") || lowerName.includes("client")) return iconsMap["victim"];
            return iconsMap["authoritative"]; 
        }}

        function getTypeIcon(type) {{
            const lowerType = type.toLowerCase();
            if (lowerType.includes("query") || lowerType.includes("ask")) return iconsMap["query"];
            if (lowerType.includes("referral") || lowerType.includes("redirect")) return iconsMap["referral"];
            if (lowerType.includes("timeout") || lowerType.includes("wait")) return iconsMap["timeout"];
            if (lowerType.includes("loop") || lowerType.includes("retry")) return iconsMap["loop"];
            if (lowerType.includes("attack") || lowerType.includes("flood")) return iconsMap["attack"];
            if (lowerType.includes("error") || lowerType.includes("fail")) return iconsMap["error"];
            return iconsMap["query"];
        }}
        
        // Flatten into timeline architecture structure and attach color data payloads
        let allSteps = [];
        attackData.forEach((p, pIdx) => {{
            const phaseColor = phaseColorsPalette[pIdx % phaseColorsPalette.length];
            p.steps.forEach(s => {{
                allSteps.push({{
                    phaseTitle: p.phase,
                    phaseColor: phaseColor, 
                    involvedEntities: p.involved_entities,
                    ...s
                }});
            }});
        }});

        let currentGlobalIndex = 0;
        let lastPhaseTitle = null;
        let isPlaying = true;
        let intervalId = null;
        
        const BASE_DURATION = 6000; 
        let currentSpeedMultiplier = 1;

        const phaseTitleEl = document.getElementById('phase-title');
        const architectureMapEl = document.getElementById('architecture-map');
        const progressIndicatorEl = document.getElementById('progress-indicator');
        const progressBarEl = document.getElementById('progress-bar');
        const stepBoxEl = document.getElementById('step-box');
        const stepNumberEl = document.getElementById('step-number');
        const stepTypeIconEl = document.getElementById('step-type-icon');
        const stepTitleEl = document.getElementById('step-title');
        const stepDescEl = document.getElementById('step-desc');
        const stepInsightEl = document.getElementById('step-insight');
        const insightContainerEl = document.getElementById('insight-container');
        const stepFlowEl = document.getElementById('step-flow');
        const flowBadgeContainerEl = document.getElementById('flow-badge-container');
        
        const playBtnEl = document.getElementById('btn-play');
        const pauseBtnEl = document.getElementById('btn-pause');
        const restartBtnEl = document.getElementById('btn-restart');
        const speedLabelEl = document.getElementById('speed-label');

        function buildInitialMap() {{
            architectureMapEl.innerHTML = '';
            allEntities.forEach(ent => {{
                const card = document.createElement('div');
                card.id = `entity-node-${{btoa(unescape(encodeURIComponent(ent)))}}`;
                card.style.cssText = "background: var(--background-color, #21262d); padding: 10px 14px; border-radius: 8px; font-size: 0.85rem; font-weight: 500; border: 1px solid var(--secondary-background-color, #30363d); opacity: 0.4; transform: scale(0.95); transition: all 0.5s ease; min-width: 130px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); display: flex; flex-direction: column; align-items: center; gap: 8px;";
                
                const img = document.createElement('img');
                img.src = getEntityIcon(ent);
                img.style.cssText = "width: 32px; height: 32px;";
                
                const label = document.createElement('span');
                label.innerText = ent;
                
                card.appendChild(img);
                card.appendChild(label);
                architectureMapEl.appendChild(card);
            }});
        }}

        function updateDisplay() {{
            if (allSteps.length === 0) return;
            const currentData = allSteps[currentGlobalIndex];
            const activePhaseColor = currentData.phaseColor;
            
            stepBoxEl.style.opacity = '0';
            stepBoxEl.style.transform = 'translateY(10px)';
            
            if (phaseTitleEl.innerText !== currentData.phaseTitle) {{
                phaseTitleEl.style.opacity = '0';
            }}

            setTimeout(() => {{
                // Update header title, loader bar, box border left edge, and step badge colors
                phaseTitleEl.innerText = currentData.phaseTitle;
                phaseTitleEl.style.color = activePhaseColor; 
                progressBarEl.style.background = activePhaseColor;
                stepBoxEl.style.borderLeftColor = activePhaseColor;
                stepNumberEl.style.backgroundColor = activePhaseColor;
                
                stepNumberEl.innerText = `Step ${{currentData.num}}`;
                stepTitleEl.innerText = currentData.title;
                stepDescEl.innerText = currentData.desc;
                
                const typeIconSrc = getTypeIcon(currentData.title);
                if (typeIconSrc) {{
                    stepTypeIconEl.src = typeIconSrc;
                    stepTypeIconEl.style.display = 'inline-block';
                }} else {{
                    stepTypeIconEl.style.display = 'none';
                }}

                if (currentData.insight) {{
                    stepInsightEl.innerText = currentData.insight;
                    insightContainerEl.style.display = 'block';
                }} else {{
                    insightContainerEl.style.display = 'none';
                }}
                
                // DYNAMIC FIX: Update Flow Path Badge (text & background colors matching the phase)
                if (currentData.source && currentData.target) {{
                    stepFlowEl.innerHTML = `<b>${{currentData.source}}</b> ➔ <b>${{currentData.target}}</b>`;
                    flowBadgeContainerEl.style.color = activePhaseColor;
                    flowBadgeContainerEl.style.backgroundColor = getTransparentColor(activePhaseColor, 0.12);
                    flowBadgeContainerEl.style.display = 'flex';
                }} else {{
                    flowBadgeContainerEl.style.display = 'none';
                }}
                
                allEntities.forEach(ent => {{
                    const cardId = `entity-node-${{btoa(unescape(encodeURIComponent(ent)))}}`;
                    const cardEl = document.getElementById(cardId);
                    if (cardEl) {{
                        const isPart = currentData.involvedEntities.includes(ent);
                        const isSource = currentData.source === ent;
                        const isTarget = currentData.target === ent;
                        
                        if (isPart) {{
                            if (isSource) {{
                                cardEl.style.background = "rgba(255, 75, 75, 0.12)";
                                cardEl.style.borderColor = "#ff4b4b";
                            }} else if (isTarget) {{
                                cardEl.style.background = "rgba(31, 111, 235, 0.12)";
                                cardEl.style.borderColor = "#1f6feb";
                            }} else {{
                                cardEl.style.background = "rgba(35, 134, 54, 0.12)";
                                cardEl.style.borderColor = "#238636";
                            }}
                            cardEl.style.opacity = "1";
                            cardEl.style.transform = "scale(1.03)";
                            cardEl.style.boxShadow = "0 4px 12px rgba(0,0,0,0.15)";
                        }} else {{
                            cardEl.style.background = "var(--background-color, #21262d)";
                            cardEl.style.borderColor = "var(--secondary-background-color, #30363d)";
                            cardEl.style.opacity = "0.25";
                            cardEl.style.transform = "scale(0.95)";
                            cardEl.style.boxShadow = "none";
                        }}
                    }}
                }});
                
                progressIndicatorEl.innerText = `Step ${{currentGlobalIndex + 1}} of ${{allSteps.length}}`;
                const progressPercent = ((currentGlobalIndex + 1) / allSteps.length) * 100;
                progressBarEl.style.width = `${{progressPercent}}%`;

                phaseTitleEl.style.opacity = '1';
                stepBoxEl.style.transform = 'translateY(0px)';
                stepBoxEl.style.opacity = '1';
            }}, 300);
        }}

        function updateSpeed(val) {{
            currentSpeedMultiplier = parseInt(val);
            speedLabelEl.innerText = `${{currentSpeedMultiplier}}x`;
            if (isPlaying) {{
                resetInterval();
            }}
        }}

        function nextStep() {{
            if (allSteps.length === 0) return;
            currentGlobalIndex = (currentGlobalIndex + 1) % allSteps.length;
            updateDisplay();
            if (isPlaying) resetInterval();
        }}

        function prevStep() {{
            if (allSteps.length === 0) return;
            currentGlobalIndex = (currentGlobalIndex - 1 + allSteps.length) % allSteps.length;
            updateDisplay();
            if (isPlaying) resetInterval();
        }}

        function startPlay() {{
            if (isPlaying) return;
            isPlaying = true;
            
            playBtnEl.style.background = "#238636";
            playBtnEl.style.color = "white";
            playBtnEl.style.opacity = "1";
            pauseBtnEl.style.background = "transparent";
            pauseBtnEl.style.color = "var(--text-color, #8b949e)";
            pauseBtnEl.style.opacity = "0.6";
            
            resetInterval();
            nextStep();
        }}

        function pausePlay() {{
            if (!isPlaying) return;
            isPlaying = false;
            clearInterval(intervalId);
            
            pauseBtnEl.style.background = "#ff4b4b";
            pauseBtnEl.style.color = "white";
            pauseBtnEl.style.opacity = "1";
            playBtnEl.style.background = "transparent";
            playBtnEl.style.color = "var(--text-color, #8b949e)";
            playBtnEl.style.opacity = "0.6";
        }}

        function restartPlay() {{
            currentGlobalIndex = 0;
            updateDisplay();
            if (isPlaying) {{
                resetInterval();
            }}
        }}

        function resetInterval() {{
            clearInterval(intervalId);
            const dynamicallyComputedDuration = BASE_DURATION / currentSpeedMultiplier;
            intervalId = setInterval(nextStep, dynamicallyComputedDuration);
        }}

        buildInitialMap();
        updateDisplay();
        
        playBtnEl.style.background = "transparent";
        playBtnEl.style.color = "var(--text-color, #8b949e)";
        playBtnEl.style.opacity = "0.6";
        pauseBtnEl.style.background = "#ff4b4b";
        pauseBtnEl.style.color = "white";
        
        if (isPlaying) resetInterval();
    </script>
    """

    st.components.v1.html(animation_html, height=650, scrolling=False)