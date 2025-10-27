# ==================== CIS_OFF_AURORA_v3_3.py — PART 1/5 ====================
# Aurora v3.2 (NEXUS) — "CIS Integrated+"
# Przywrócone z v2.7:
#   • Oracle Touch (ownership surface, mutable caps, one-block, lock hints, secrets, heatmap)
#   • Reachability (pause/fee/upgrade) + Explain v2
#   • Legacy CEX / Treasury detection (Patch #24–#26)
# Zachowane i zintegrowane z v3.0:
#   • Patch #28: DAO-Uplift (+0..+3; cap 8.8; blokada przy red flags)
#   • Patch #29: Router Exception + TaxCapSoftening (≤25% lub fee-cap → limit kary do −2)
#   • Patch #30: Name Resolution & Labeling (Name/Symbol, is_proxy, confidence + label w konsoli)
# NOWE — Patch #31 (v3.2):
#   • Governance-aware RUG_DISTANCE v2 (timelock/multisig/proxyadmin/governor)
#   • Proxy softening pod governance, LayerZero/OFT whitelist
#   • Blue-chip floor (adresy znanych tokenów), nowy label „GOV-UPGRADABLE (review)”
#   • Nazwa tokena w ANALYZE/*.txt i w logach zamiast „Contract”

import os, re, json, time, argparse, requests
from typing import Optional, Tuple, List, Dict

def _ts(): return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
def log_info(msg): print(f"[INFO ] {_ts()} | {msg}")
def log_ok(msg):   print(f"[ OK  ] {_ts()} | {msg}")
def log_warn(msg): print(f"[WARN ] {_ts()} | {msg}")
def log_err(msg):  print(f"[ERR  ] {_ts()} | {msg}")

BANNER = r"""
╔══════════════════════════════════════════════════════════════════════╗
║  CIS — Contract Integrator System | OFF Console — AURORA v3.3 (NX)  ║
║  Core: ERC-20 Heuristics + Oracle Touch + DAO/Router/Labeling + Gv. ║
╚══════════════════════════════════════════════════════════════════════╝
Legend: GOOD (≥8.0) | RISK (6.5–7.99) | GOV-UPGRADABLE (review) | EXTREME (<6.5)
"""

# ------------------ ENV / Config ------------------
ETHERSCAN_API_KEY = "DAETNG8213K5PSWVNUVUNX1B17A9FM3XM1"

GOOD_SNAP_MIN = float(os.getenv("GOOD_SNAP_MIN", "7.60"))
REPORT_MODE   = os.getenv("AURORA_REPORT_MODE", "BRIEF")      # BRIEF | VERBOSE
AURORA_MODE   = os.getenv("AURORA_MODE", "PRO").upper()       # BEGINNER | PRO
EVIDENCE_BUDGET = int(os.getenv("AURORA_EVIDENCE_BUDGET", "6"))
VANILLA_OZ_UPLIFT = float(os.getenv("AURORA_VANILLA_OZ_UPLIFT", "0.7"))

AURORA_D_MAX_FULL = int(os.getenv("AURORA_D_MAX_FULL", "2"))
AURORA_D_SOFT     = int(os.getenv("AURORA_D_SOFT", "2"))

# Patch #28
DAO_UPLIFT_MAX = int(os.getenv("AURORA_DAO_UPLIFT_MAX", "3"))
DAO_GOOD_CAP   = float(os.getenv("AURORA_DAO_GOOD_CAP", "8.8"))

# Patch #29
ROUTER_EXCEPTION_ON = os.getenv("AURORA_ROUTER_EXCEPTION", "ON").upper() == "ON"
TAX_SOFTENING_ON    = os.getenv("AURORA_TAX_SOFTENING", "ON").upper() == "ON"

# Oracle Touch knobs (z 2.7)
ORACLE_ONEBLOCK_FEE_THRESHOLD = float(os.getenv("AURORA_ORACLE_ONEBLOCK_FEE", "30.0"))
ORACLE_SECRET_TABLE_LEN       = int(os.getenv("AURORA_ORACLE_SECRET_LEN", "256"))
LEGACY_MODE = os.getenv("AURORA_LEGACY_MODE", "ON").upper()    # ON | OFF

# I/O
CONTRACTS_DIR = "contracts"
ANALYZE_ROOT  = "ANALYZE"
ANALYZE_DIRS  = {
    "good": os.path.join(ANALYZE_ROOT, "GOOD"),
    "risk": os.path.join(ANALYZE_ROOT, "RISK"),
    "extreme_risk": os.path.join(ANALYZE_ROOT, "EXTREME_RISK"),
}
for d in [CONTRACTS_DIR] + list(ANALYZE_DIRS.values()):
    os.makedirs(d, exist_ok=True)
ROTATION_LIMIT = 200

# ------------------ Opisy flag ------------------
flag_explanations = {
    'require(!tradingOpen)': "Trading gate – handel wyłączony do czasu otwarcia.",
    'pause': "Pauza – właściciel/rola może zatrzymać transfery (reach).",
    'blacklist': "Czarna lista – blokowanie adresów.",
    'whitelist': "Biała lista – preferencje dla adresów.",
    'maxTxAmount': "Limit pojedynczej transakcji.",
    'maxWalletSize': "Limit posiadania na portfel.",
    'mint': "Mint – możliwość rozwodnienia podaży.",
    'mint100_owner': "Wszystkie minty do owner-like.",
    'oz_import': "OpenZeppelin w kodzie.",
    'big_supply_1e9': "Duża podaż bazowa (≥5e9).",
    'highTaxOver25': "Podatki/opłaty ≥25%.",
    'swapTokensForEth': "Ścieżki swapu (router).",
    'manualSwap': "Manualne swapy (często drain).",
    'manualSend': "Ręczny przelew ETH (często drain).",
    'sendETHToFee': "Przelew ETH do portfela opłat.",
    'delegatecall': "delegatecall – proxy/upgrade (reach).",
    'implementation': "Pole implementation (reach).",
    'upgradeTo': "upgradeTo – aktualizacja logiki (reach).",
    'proxy': "Kontrakt aktualizowalny (reach).",
    'dynamic_tax_expr': "Dynamiczne wyliczenia podatku/fee w kodzie.",
    'hidden_swap_gate': "Ukryta bramka swapów (early-return).",
    'sell_limit_after_open': "Sprzedaż limitowana blokiem/czasem po otwarciu.",
    'tax_no_cap': "Są tax/marketing/dev, ale brak cap/maxSupply.",
    'aurora_long_hex_string': "Długie hexy – możliwa obfuskacja.",
    'aurora_base64_like': "Ciągi base64-like – możliwy payload.",
    'aurora_obfusk_var': "Identyfikatory sugerujące obfuskację.",
    'aurora_large_bitshift': "Duże przesunięcia bitowe.",
    'aurora_many_numeric_literals': "Mnóstwo dużych literałów.",
    'aurora_minified_like': "Wygląda na zminifikowany/auto-generated.",
    'oldSolidityVersion': "Stara wersja Solidity.",
    'approveAndCall': "Przestarzały approveAndCall.",
    'receiveApproval': "Przestarzały receiveApproval.",
    'multiTransfer': "Masowe transfery.",
    'lp_to_owner_addLiquidity': "LP dodane na ownera / brak locka.",
    'eth_skimmer_on_sell': "Skimmer ETH przy SELL (przepływ do tax wallet).",
    'allowance_bypass_tax_wallet': "Backdoor allowance/bypass pod tax wallet.",
    'conditional_transfer_event': "Manipulacja eventami (Transfer zależny).",
    'dead_to_zero_swap': "Zamiana dead→0x0 w zdarzeniach (zaciemnianie).",
    'silent_drop_no_event': "Transfery bez eventu (ciche dropy).",
    'time_lock_after_buy': "Okresowa blokada sprzedaży po BUY.",
    'sellCount': "Licznik SELL (często dynamiczne fee/limity).",
    'balance_wipe_swap': "Wipe sald przy swapie (nienormatywny ERC-20).",
    'fake_burn_mint_to_addr': "„Burn” maskujący mint na adres.",
    'tx_origin_logic': "Logika warunkowana tx.origin (origin-gated).",
    'generic_suspicious_fn_name': "Podejrzane nazwy funkcji finansowych.",
    'generic_transfer_call': "Bezpośrednie .transfer() (ryzyko drenażu).",
    'generic_send_fee_wallet_in_body': "W ciele funkcji wysyłki na fee wallet.",
    # Legacy
    'legacy_cex_signature': "Sygnatura legacy CEX/treasury (solc 0.4.x; full supply; approveAndCall; bez fee/pause/proxy).",
    'burn_nonstandard': "Burn bez Transfer(..., 0x0).",
    'manual_overflow_checks': "Ręczne require/assert zamiast SafeMath (styl 0.4.x).",
    # v3.0 special
    'router_exception': "Znany DEX Router – neutralizacja skimmer false-positive.",
}

# ------------------ Kategorie / wagi ------------------
categories = {
    "Wykryto wysokie podatki lub opłaty": ['highTaxOver25','dynamic_tax_expr','setTax','setFee','updateFee','taxFee','marketingFee','devFee'],
    "Wykryto funkcję mint": ['mint'],
    "Mint 100% do ownera": ['mint100_owner'],
    "Cooldown / Tax-Router Drain": ['manualSwap','sendETHToFee','manualSend','swapTokensForEth'],
    "OpenZeppelin w kodzie (OZ)": ['oz_import'],
    "Duża podaż (≥ 5 000 000 000)": ['big_supply_1e9'],
    "Charakterystyka honeypot": ['require(!tradingOpen)','sell_limit_after_open'],
    "Wykryto mechanizmy swap": ['swapTokensForEth','manualSwap'],
    "Kontrakt może być wstrzymany": ['pause'],
    "Wykryto ograniczenia transferu": ['blacklist','whitelist','maxTxAmount','maxWalletSize'],
    "Właściciel może wypłacać środki": ['manualSend','sendETHToFee'],
    "Wykryto kontrakt aktualizowalny": ['delegatecall','implementation','upgradeTo','proxy'],
    "Centralizacja kontroli dostępu": ['mint100_owner','pause','require(!tradingOpen)'],
    "Wykryto przestarzałe wzorce": ['oldSolidityVersion','approveAndCall','receiveApproval','multiTransfer'],
    "Rug: LP u właściciela / brak locka": ['lp_to_owner_addLiquidity'],
    "Skimmer ETH / drenaż do tax walleta": ['eth_skimmer_on_sell','generic_transfer_call','generic_send_fee_wallet_in_body'],
    "Backdoor allowance/kradzież": ['allowance_bypass_tax_wallet'],
    "Manipulacja eventami / burn obfuscation": ['conditional_transfer_event','dead_to_zero_swap','silent_drop_no_event'],
    "Wykryto limiter transakcji": ['sellCount','maxTxAmount','maxWalletSize'],
    "Nienormatywny ERC-20: wipe/mint pod burnem": ['balance_wipe_swap','fake_burn_mint_to_addr'],
    "Origin-gated logika": ['tx_origin_logic'],
    "Podejrzane funkcje finansowe": ['generic_suspicious_fn_name','generic_transfer_call','generic_send_fee_wallet_in_body'],
    "Legacy CEX / Treasury Token (statyczny)": ['legacy_cex_signature','manual_overflow_checks','burn_nonstandard'],
    "Kill-Switch / honeypot gate": ['kill_switch'],
}


category_weights = {
    "Wykryto wysokie podatki lub opłaty": 4,
    "Wykryto funkcję mint": 4,
    "Mint 100% do ownera": 4,
    "Cooldown / Tax-Router Drain": 4,
    "OpenZeppelin w kodzie (OZ)": 2,
    "Duża podaż (≥ 5 000 000 000)": 2,
    "Charakterystyka honeypot": 4,
    "Wykryto mechanizmy swap": 4,
    "Kontrakt może być wstrzymany": 4,
    "Wykryto ograniczenia transferu": 2,
    "Właściciel może wypłacać środki": 2,
    "Wykryto kontrakt aktualizowalny": 2,
    "Centralizacja kontroli dostępu": 2,
    "Wykryto przestarzałe wzorce": 2,
    "Rug: LP u właściciela / brak locka": 4,
    "Skimmer ETH / drenaż do tax walleta": 4,
    "Backdoor allowance/kradzież": 4,
    "Manipulacja eventami / burn obfuscation": 2,
    "Wykryto limiter transakcji": 2,
    "Nienormatywny ERC-20: wipe/mint pod burnem": 4,
    "Origin-gated logika": 4,
    "Podejrzane funkcje finansowe": 2,
    "Legacy CEX / Treasury Token (statyczny)": 1,
    "Kill-Switch / honeypot gate": 4,
}

# ------------------ Regex utils ------------------
def _brace_match_end(src: str, start_idx: int) -> Optional[int]:
    depth = 0
    for i in range(start_idx, len(src)):
        ch = src[i]
        if ch == '{': depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0: return i
    return None

CONTRACT_DEF_RE = re.compile(r"contract\s+([A-Za-z0-9_]+)\s*(?:is\s+[^{]+)?\{", re.IGNORECASE)
FUNC_DEF_RE     = re.compile(r"function\s+([A-Za-z0-9_]+)\s*\([^)]*\)\s*([^{;]*?)\{", re.IGNORECASE)

OZ_HINTS = ('@openzeppelin/contracts','abstract contract ERC20','contract ERC20','library SafeMath',
            'abstract contract Ownable','contract Ownable','interface IERC20','ERC20Permit')# --- Trusted libs / routers / factories (whitelist) ---
TRUSTED_IMPORTS_RX = re.compile(
    r'@uniswap|UniswapV2Router02|UniswapV3Router|Sushi(Router|Swap)|Pancake(Router|Factory)|'
    r'V2Router|V3Router|IUniswapV2Router|IUniswapV3Router|quoter|swapRouter|WETH9',
    re.IGNORECASE
)
TRUSTED_FACTORY_RX = re.compile(
    r'I?UniswapV2Factory|I?UniswapV3Factory|PancakeFactory|SushiFactory|Factory\(.*\)',
    re.IGNORECASE
)
TRUSTED_LAYERZERO_RX = re.compile(r'LayerZero|lzApp|Endpoint|OFT|OFTV2|Stargate', re.IGNORECASE)

ROUTER_INSTANCE_RX = re.compile(
    r'(I?UniswapV2Router02|I?UniswapV3Router|PancakeRouter|SushiRouter)\s+\w+|'
    r'(?:uniswapV2Router|swapRouter|router)\s*=\s*(?:I?UniswapV[23]Router0?2|PancakeRouter|SushiRouter)\s*\(',
    re.IGNORECASE
)
ADDR_LITERAL_RX = re.compile(r'0x[a-fA-F0-9]{40}')  # reserved (future use)

def is_trusted_router_context(source_code: str) -> bool:
    if TRUSTED_IMPORTS_RX.search(source_code) and has_router_instance(source_code): return True
    if TRUSTED_FACTORY_RX.search(source_code): return True
    if TRUSTED_LAYERZERO_RX.search(source_code): return True
    return False

def has_router_instance(source_code: str) -> bool:
    if ROUTER_INSTANCE_RX.search(source_code):
        # literal adresu mile widziany, ale nie wymagany (często przekazywany parametrem)
        return True
    return False


def extract_project_functions(source: str):
    funcs = []
    for c in CONTRACT_DEF_RE.finditer(source):
        cname = c.group(1); start = c.end()-1; end_idx = _brace_match_end(source, start)
        if end_idx is None: continue
        block = source[start:end_idx]
        if any(h in block for h in OZ_HINTS) and cname.lower() in {"erc20","ownable","erc20capped","erc20burnable","erc20permit"}:
            continue
        for f in FUNC_DEF_RE.finditer(block):
            f_name = f.group(1); body_open = source.find('{', f.end())
            if body_open == -1 or body_open > end_idx: continue
            f_end = _brace_match_end(source, body_open); 
            if f_end is None: continue
            body = source[body_open+1:f_end]
            s_line = source.count('\n', 0, body_open) + 1
            e_line = source.count('\n', 0, f_end) + 1
            funcs.append({"contract": cname, "name": f_name, "start_idx": body_open, "end_idx": f_end,
                          "body": body, "start_line": s_line, "end_line": e_line})
    return funcs

def _slugify(s: str, max_len: int = 48) -> str:
    s = (s or "").strip()
    if not s: return "contract"
    s = re.sub(r'[^A-Za-z0-9]+', '-', s)
    s = re.sub(r'-{2,}', '-', s).strip('-')
    return (s[:max_len] or "contract").lower()

# ==================== CIS_OFF_AURORA_v3_2.py — PART 2/5 ====================

# -------- High-Tax detection --------
HIGH_TAX_VARNAMES = r'(?:_?(?:initial|final)?(?:Buy|Sell)?(?:Tax|Fee)|taxFee|marketingFee|devFee|_transferTax|buyTax|sellTax|fee)'
ASSIGN_NUM_PATTERN = re.compile(rf'\b({HIGH_TAX_VARNAMES})\s*=\s*(\d{{1,6}})\s*;', re.IGNORECASE)
CALL_NUM_PATTERN   = re.compile(rf'\bset(?:Tax|Fees?)\s*\(\s*(\d{{1,6}})\s*\)', re.IGNORECASE)

def _infer_percent(value: int, src: str) -> float:
    """
    Heurystyka rozpoznająca:
     - basis points (2500 -> 25.00)
     - proste dzielenia X/100
     - formy (X*100)/denom lub X*1e2/denom
    Zwraca wartość w procentach (np. 5.0).
    """
    s_src = str(src)
    # 1) jeśli literal value wydaje się >1000 to często basis points
    try:
        v = float(value)
    except:
        return float(value)
    if v > 1000:
        return round(v / 100.0, 4)

    # 2) gdy w źródle występuje /10000 lub /1e4 -> value/100
    if re.search(r'/\s*(?:10000|1e4)\b', s_src): return round(v / 100.0, 4)
    # 3) gdy /1000 lub /1e3 -> value/10
    if re.search(r'/\s*(?:1000|1e3)\b', s_src):  return round(v / 10.0, 4)

    # 4) proste wyrażenie (X/100)
    if re.search(r'\b\d+\s*\/\s*100\b', s_src):
        return round(v, 4)

    # 5) wyrażenia (X*100)/Y lub (X*1e2)/Y
    m = re.search(r'(\d+(?:\.\d+)?)\s*(?:\*1e2|\*100)\s*\/\s*(\d+(?:\.\d+)?)', s_src)
    if m:
        num = float(m.group(1)) * 100.0
        den = float(m.group(2))
        if den != 0:
            return round(num / den, 4)

    return float(v)

def detect_high_tax_over_25(source_code: str):
    hits = []
    for m in ASSIGN_NUM_PATTERN.finditer(source_code):
        var, raw = m.group(1), int(m.group(2)); pct = _infer_percent(raw, source_code)
        if pct >= 25.0: hits.append((var, pct))
    for m in CALL_NUM_PATTERN.finditer(source_code):
        raw = int(m.group(1)); pct = _infer_percent(raw, source_code)
        if pct >= 25.0: hits.append(("setTax/Fees", pct))
    return hits

def detect_any_tax_settings(source_code: str):
    any_hits = []
    for m in ASSIGN_NUM_PATTERN.finditer(source_code):
        var, raw = m.group(1), int(m.group(2)); pct = _infer_percent(raw, source_code)
        any_hits.append((var, pct))
    for m in CALL_NUM_PATTERN.finditer(source_code):
        raw = int(m.group(1)); pct = _infer_percent(raw, source_code)
        any_hits.append(("setTax/Fees", pct))
    return any_hits

# -------- Market Matrix --------
def _get_function_body(source: str, name: str) -> Optional[str]:
    for f in FUNC_DEF_RE.finditer(source):
        if f.group(1) == name:
            body_open = source.find('{', f.end())
            if body_open == -1: continue
            body_end = _brace_match_end(source, body_open)
            if body_end is None: continue
            return source[body_open+1:body_end]
    return None

def _blocks_sell_reasons(code: str) -> List[str]:
    r = []
    if re.search(r'require\s*\(\s*(?:recipient|to)\s*!=\s*(?:uniswapV2Pair|pair)\s*,', code, re.IGNORECASE):
        r.append("require(to!=pair)")
    if re.search(r'if\s*\(\s*(?:recipient|to)\s*==\s*(?:uniswapV2Pair|pair)\s*\)\s*(?:revert|require\s*\()', code, re.IGNORECASE):
        r.append("if(to==pair)→revert/require")
    return r

def _blocks_buy_reasons(code: str) -> List[str]:
    r = []
    if re.search(r'require\s*\(\s*(?:sender|from)\s*!=\s*(?:uniswapV2Pair|pair)\s*,', code, re.IGNORECASE):
        r.append("require(from!=pair)")
    if re.search(r'if\s*\(\s*(?:sender|from)\s*==\s*(?:uniswapV2Pair|pair)\s*\)\s*(?:revert|require\s*\()', code, re.IGNORECASE):
        r.append("if(from==pair)→revert/require")
    return r

def _blocks_p2p_reasons(code: str) -> List[str]:
    r = []
    if re.search(r'\b(whitelist|blacklist|bots)\b.*(require|revert)', code, re.IGNORECASE | re.DOTALL):
        r.append("list gate (wl/bl/bots)")
    if re.search(r'\bcooldown\b', code, re.IGNORECASE):
        r.append("cooldown gate")
    return r

def build_market_matrix(source: str) -> Dict[str, Dict[str, str]]:
    code = _get_function_body(source, "_transfer") or ""
    return {
        "SELL(user→pair)": "FAIL: " + "; ".join(_blocks_sell_reasons(code)) if _blocks_sell_reasons(code) else "PASS",
        "BUY(pair→user)":  "FAIL: " + "; ".join(_blocks_buy_reasons(code))  if _blocks_buy_reasons(code)  else "PASS",
        "P2P(user→user)":  "FAIL: " + "; ".join(_blocks_p2p_reasons(code))  if _blocks_p2p_reasons(code)  else "PASS"
    }

# -------- Permission lattice & Rug Distance (v1 base) --------
ROLE_ONLYOWNER = re.compile(r'\bonlyOwner\b|\brequire\s*\(\s*msg\.sender\s*==\s*(?:owner|_owner)\b', re.IGNORECASE)
ROLE_ONLYROLE  = re.compile(r'\bonlyRole\s*\(\s*([A-Za-z0-9_]+)\s*\)', re.IGNORECASE)
HAS_ROLE_CHECK = re.compile(r'hasRole\s*\(\s*([A-Za-z0-9_]+)\s*,', re.IGNORECASE)
TIMELOCK_HINT  = re.compile(r'\bTimelockController\b|\bTIMELOCK_ROLE\b', re.IGNORECASE)
MULTISIG_HINT  = re.compile(r'\bOwners\b|\bconfirmTransaction\b|\brequired\b', re.IGNORECASE)
GOVERNOR_HINT  = re.compile(r'\bGovernor\b|\bGovernorCompatibility\b|\bGovernorVotes\b', re.IGNORECASE)

def _func_guard(source: str, fname: str) -> Dict[str, str]:
    body = _get_function_body(source, fname) or ""
    guard = []
    if ROLE_ONLYOWNER.search(body): guard.append("onlyOwner")
    m = ROLE_ONLYROLE.search(body)
    if m: guard.append(f"onlyRole({m.group(1)})")
    if TIMELOCK_HINT.search(source) and ("onlyRole" in " ".join(guard) or HAS_ROLE_CHECK.search(body)):
        guard.append("timelock-ish")
    if MULTISIG_HINT.search(source): guard.append("multisig-ish")
    return {"function": fname, "guard": "+".join(guard) or "none"}

GOALS = {"set_fee_99":["setTax","setFees","updateFee"], "pause_market":["pause"], "upgrade_impl":["upgradeTo","upgradeToAndCall"]}  # reserved (future use)

# -------- Fee Taint --------
FEE_NAMES = r'(?:taxFee|buyTax|sellTax|_transferTax|marketingFee|devFee|fee)'
SINKS = (r'_transfer', r'swapBack', r'sendETHToFee', r'manualSend')

def fee_taint_analysis(source: str) -> Dict[str, List[Dict[str,str]]]:
    flows = []
    for m in re.finditer(rf'({FEE_NAMES})\s*=\s*([_A-Za-z0-9+\-*/().\s]+);', source, re.IGNORECASE):
        name, expr = m.group(1), m.group(2).strip()
        sinks_hit = []
        for s in SINKS:
            if re.search(rf'\b{s}\b[\s\S]{{0,500}}{name}', source, re.IGNORECASE) or re.search(rf'{name}[\s\S]{{0,500}}\b{s}\b', source, re.IGNORECASE):
                sinks_hit.append(s)
        guarded = bool(re.search(rf'require\s*\(\s*{name}\s*<=\s*[A-Za-z0-9_]+\s*[,)]', source))
        flows.append({"var": name, "expr": expr[:80], "sinks": ",".join(sorted(set(sinks_hit))) or "-", "guarded_cap": "yes" if guarded else "no"})
    return {"flows": flows}

# -------- Tri skrót --------
def _supermetrics_detect_three(source_code: str):
    src = source_code or ""; s_lower = src.lower()
    mint_calls_total = len(re.findall(r'(?<!function\s)_mint\s*\(', src, re.IGNORECASE))
    owner_like_calls = len(re.findall(r'_mint\s*\(\s*(?:owner\s*\(\s*\)|_owner|msg\.sender|_msgSender\s*\(\s*\))\s*,', src, re.IGNORECASE))
    mint100_owner = (mint_calls_total > 0 and owner_like_calls == mint_calls_total)
    oz_used = ('openzeppelin' in s_lower)

    # --- Patch #33: rozszerzone wykrywanie „extreme supply” ---
    base_guess = None
    # wariant 1: N * (1eX | 10**decimals)
    m_supply = re.search(r'(\d[\d_]*)\s*\*\s*(?:1e(\d{1,3})|10\s*\*\*\s*(?:decimals|_decimals|\w+))', src, re.IGNORECASE)
    if m_supply:
        try:
            base_guess = int(m_supply.group(1).replace('_',''))
        except:
            base_guess = None
    big_supply = bool(base_guess is not None and base_guess >= 5_000_000_000)

    return {"mint100_owner": mint100_owner, "oz_import": oz_used, "big_supply_1e9": big_supply}

# -------- AURORA-D wagi --------
def weight_D(flag: str, guarded_cap: bool, has_drain: bool) -> int:
    base = 12
    if flag == 'dynamic_tax_expr' and guarded_cap: base = 6
    if flag == 'tax_no_cap': base = 12 if has_drain else 6
    return base

# -------- DeepFusion — twarde regexy --------
DEEP_REGEX = {
    'lp_to_owner_addLiquidity': r'addLiquidityETH(?:\s*\{[^}]*\})?\s*\([^,]*,\s*[^,]*,\s*[^,]*,\s*[^,]*,\s*owner\s*\(\s*\)\s*,',
    'eth_skimmer_on_sell': r'(?:to|recipient)\s*==\s*(?:uniswapV2Pair|pair)[\s\S]*?swapExactTokensForETH(?:SupportingFeeOnTransferTokens)?[\s\S]*?(?:sendETHToFee|transfer)\s*\(\s*address\s*\(\s*this\s*\)\.balance',
    'allowance_bypass_tax_wallet': r'_spendAllowance\s*\([^)]*\)|transferFrom\s*\([\s\S]*?(?:_tAmount|bypass|ignoreAllowance)[\s\S]*?\)',
    'conditional_transfer_event': r'if\s*\(\s*to\s*!=\s*(?:0xdead|address\s*\(\s*0xdead\s*\))\s*\)\s*emit\s+Transfer',
    'dead_to_zero_swap': r'if\s*\(\s*to\s*==\s*address\s*\(\s*0xdead\s*\)\s*\)\s*\{[\s\S]*?to\s*=\s*address\s*\(\s*0\s*\)\s*;',
    'silent_drop_no_event': r'function\s+_transfer\s*\([\s\S]*?\{[\s\S]*?return\s*;\s*\}[\s\S]*?(?!emit\s+Transfer)',
    'time_lock_after_buy': r'(?:buyBlock|firstBuyBlock|DELAY_BLOCKS)[\s\S]*?block\.number',
    'sellCount': r'\bsellCount\b',
    'fake_sell_event': r'emit\s+Transfer\s*\(\s*\w+\s*,\s*(?:uniswapV2Pair|pair)\s*,\s*1\s*\)\s*;',
    'balance_wipe_swap': r'function\s+swap\s*\([^)]+\)\s*(?:external|public)[\s\S]*?balances?\s*\[[^\]]+\]\s*=\s*0',
    'fake_burn_mint_to_addr': r'function\s+burn\s*\(\s*address\s+[^)]*\)\s*\{[\s\S]*?_balances?\s*\[[^\]]+\]\s*=\s*_totalSupply',
    'tx_origin_logic': r'\btx\.origin\b|_msgData\s*\(\s*\)[\s\S]*?tx\.origin',
    'generic_suspicious_fn_name': r'function\s+\w*(?:send|fee|wallet)\w*\s*\(',
    'generic_transfer_call': r'\.transfer\s*\(',
    'generic_send_fee_wallet_in_body': r'function\s+\w+\s*\([^)]*\)\s*(?:external|public|internal|private)?[\s\S]*?(?:\bsend\b|\bfee\b|\bwallet\b)',
}# ---- PATCH 6: Kill-Switch v1 (cooldown/999-tax honeypot gate) ----
KILLSWITCH_PATTERNS = {
    "tax_999_expr": r'\.?\s*mul\s*\(\s*999\s*\)\s*\.?\s*div\s*\(\s*1000\s*\)',
    "cooldown_kw": r'\bcooldown(s|Map)?\b|\bfirst(Buy|Sell)Block\b',
    "block_number_kw": r'\bblock\.(number|timestamp)\b|getBlockNumber\s*\(',
    "owner_gate_fns": r'\b(setBots?|setCooldown|ApproveSwap|setMaxTxn|setMaxWallet|_taxWallet|marketingAddres)\b',
}
KILLSWITCH_RE = {k: re.compile(v, re.IGNORECASE | re.DOTALL) for k, v in KILLSWITCH_PATTERNS.items()}# ---- PATCH 6: Kill-Switch v2 (external burn-to-dead, obfuscation) ----
KS2_PATTERNS = {
    # Fałszywe isContract — porównanie do JEDNEGO stałego adresu (klucz wyzwalający)
    "iscontract_const": r'function\s+isContract\s*\(\s*address\s+\w+\s*\).*?returns\s*\(\s*bool\s*\)\s*\{[^}]*?address\(\s*\w+\s*\)\s*==\s*0x[0-9a-fA-F]{40}',
    # launch(addr) → _transfer(addr, dead, _balances[addr]) — zdalny wipe na 0xdead
    "launch_burn_dead": r'function\s+launch\s*\(\s*address\s+\w+\s*\)[\s\S]*?_transfer\s*\(\s*\w+\s*,\s*dead\s*,\s*_balances\s*\[\s*\w+\s*\]\s*\)',
    # Obfuskacja warunku przez XOR uint160(msg.sender) ^ uint160(uint256(...))
    "xor_uint160": r'uint160\s*\(\s*msg\.sender\s*\)\s*\^\s*uint160\s*\(\s*uint256\([^)]*\)\s*\)'
}
KS2_RE = {k: re.compile(v, re.IGNORECASE | re.DOTALL) for k, v in KS2_PATTERNS.items()}



# -------- PATCH #29 — znane Routery DEX --------
KNOWN_ROUTERS_RX = re.compile(
    r'UniswapV2Router02|PancakeRouterV2|TraderJoeRouter|SushiRouter|'
    r'UniswapV3Router|SwapRouter|V2Router|QuickswapRouter|SyncSwapRouter',
    re.IGNORECASE
)

# -------- PATCH #30 — Name Resolution & Labeling --------
ERC20_CTOR_LABEL_RE = re.compile(r'(?:ERC20|Erc20)\s*\(\s*unicode?"([^"]+)"\s*,\s*unicode?"([^"]+)"\s*\)', re.IGNORECASE)
NAME_FN_RE  = re.compile(r'function\s+name\s*\([^)]*\)\s*(?:public|external)\s*(?:view|pure)?[^{]*\{[\s\S]*?return\s+"(.*?)"', re.IGNORECASE)
SYMBOL_FN_RE= re.compile(r'function\s+symbol\s*\([^)]*\)\s*(?:public|external)\s*(?:view|pure)?[^{]*\{[\s\S]*?return\s+"(.*?)"', re.IGNORECASE)
EIP1967_SLOT_RE = re.compile(r'eip1967\.proxy\.implementation|PROXIABLE|ERC1967', re.IGNORECASE)
CONTRACT_ERC20_TITLE_RE = re.compile(r'contract\s+([A-Za-z0-9_]+)\s+is\s+[^{;]*\bERC20\b', re.IGNORECASE)
NAME_CONST_RE = re.compile(r'\bstring\s+(?:public|internal|private)?\s*name\s*=\s*"([^"]+)"', re.IGNORECASE)

def resolve_identity(src: str) -> Dict[str, str]:
    # 1) Twardy label z ERC20("Name","SYM")
    name, symbol, confidence = None, None, "low"
    m = ERC20_CTOR_LABEL_RE.search(src)
    if m:
        name, symbol, confidence = m.group(1), m.group(2), "high"
    else:
        # 2) Funkcje name()/symbol() zwracające literały
        m1 = NAME_FN_RE.search(src)
        m2 = SYMBOL_FN_RE.search(src)
        if m1:
            name, confidence = m1.group(1), "medium"
        if m2:
            symbol = m2.group(1)
            if confidence != "medium":
                confidence = "medium"

        # 3) Stała "string name = "Foo""
        if not name:
            m3 = NAME_CONST_RE.search(src)
            if m3:
                name, confidence = m3.group(1), "medium"

        # 4) Tytuł kontraktu dziedziczącego ERC20: "contract Foo is ... ERC20"
        if not name:
            m4 = CONTRACT_ERC20_TITLE_RE.search(src)
            if m4:
                name, confidence = m4.group(1), "low"

        # 5) Fallback: pierwszy kontrakt użytkownika niebędący bazą OZ
        if not name:
            for c in CONTRACT_DEF_RE.finditer(src):
                cname = c.group(1)
                if cname.lower() in {"erc20", "ownable", "erc20capped", "erc20burnable", "erc20permit", "ierc20"}:
                    continue
                start = c.end() - 1
                end_idx = _brace_match_end(src, start)
                if end_idx:
                    block = src[start:end_idx]
                    if not any(h in block for h in OZ_HINTS):
                        name, confidence = cname, "low"
                        break

    is_proxy = bool(EIP1967_SLOT_RE.search(src) or re.search(r'\bdelegatecall\b', src, re.IGNORECASE))
    return {"resolved_name": name or "", "resolved_symbol": symbol or "", "name_confidence": confidence, "is_proxy": is_proxy}

# ==================== [PATCH31] Governance & LZ/OFT helpers ====================
TIMELOCK_FPS = re.compile(r'\bTimelockController\b|\bMIN_DELAY\b|\btimelock\b', re.IGNORECASE)
GOVERNOR_FPS = re.compile(r'\bGovernor\b|\bGovernorVotes\b|\bproposalThreshold\b', re.IGNORECASE)
PROXYADMIN_FPS = re.compile(r'\bProxyAdmin\b|\bTransparentUpgradeableProxy\b|\bERC1967Proxy\b', re.IGNORECASE)
MULTISIG_FPS = re.compile(r'\bowners?\b.*\brequired\b|\bconfirmTransaction\b', re.IGNORECASE | re.DOTALL)
LAYERZERO_FPS = re.compile(r'ILayerZeroEndpoint|NonblockingLzApp|OFTCore|IOFTReceiver|OFTV2|sendFrom|lzReceive', re.IGNORECASE)

def detect_timelock(src: str) -> bool: return bool(TIMELOCK_FPS.search(src))
def detect_governor(src: str) -> bool: return bool(GOVERNOR_FPS.search(src))
def detect_proxy_admin(src: str) -> bool: return bool(PROXYADMIN_FPS.search(src))
def detect_multisig(src: str) -> bool: return bool(MULTISIG_FPS.search(src))
def is_layerzero_stack(src: str) -> bool: return bool(LAYERZERO_FPS.search(src))

# ==================== [PATCH31] RUG_DISTANCE v2 (governance-aware) ====================
def rug_distance(source: str) -> Dict[str, Dict[str, int]]:
    base = {"set_fee_99": 1, "pause_market": 1, "upgrade_impl": 1}
    has_timelock = detect_timelock(source)
    has_multisig = detect_multisig(source)
    has_proxyadmin = detect_proxy_admin(source)
    has_governor = detect_governor(source)

    uplift = 0
    if has_timelock: uplift += 1
    if has_multisig: uplift += 1
    if has_proxyadmin: uplift += 1
    if has_governor: uplift += 1

    out = {}
    out["set_fee_99"] = {"min_txs": min(4, base["set_fee_99"] + (1 if (has_timelock or has_multisig) else 0))}
    out["pause_market"] = {"min_txs": min(4, base["pause_market"] + (1 if (has_timelock or has_multisig) else 0))}
    out["upgrade_impl"] = {"min_txs": min(4, base["upgrade_impl"] + max(1, uplift))}
    return out

# ==================== CIS_OFF_AURORA_v3_2.py — PART 3/5 ====================

# -------- Oracle Touch (przywrócone) --------
OWNER_SETTERS_HINTS = [
    r'\bset(Tax|Fee|Fees?)\b', r'\bset(MaxTx|MaxWallet)\b', r'\bset(Bot|Black|White)list\b',
    r'\bpause\s*\(', r'\bunpause\s*\(', r'\bopenTrading\b', r'\bsetRouter\b', r'\bupdateRouter\b',
    r'\bgrantRole\b', r'\brevokeRole\b', r'\bupgradeTo(AndCall)?\b', r'\bsetMarketingWallet\b', r'\bsetDevWallet\b',
    r'\bmint\s*\(', r'\bburn\s*\(',
]

def oracle_ownership_surface(source: str) -> List[Dict[str, str]]:
    setters = []
    for f in FUNC_DEF_RE.finditer(source):
        name = f.group(1)
        if not any(re.search(h, name, re.IGNORECASE) for h in OWNER_SETTERS_HINTS):
            continue
        guard = _func_guard(source, name)["guard"]
        if re.search(r'(Tax|Fee)', name, re.IGNORECASE): effect = "fees"
        elif re.search(r'(MaxTx|MaxWallet)', name, re.IGNORECASE): effect = "limits"
        elif re.search(r'(Black|White)list|Bot', name, re.IGNORECASE): effect = "lists"
        elif re.search(r'pause|unpause|openTrading', name, re.IGNORECASE): effect = "market_gate"
        elif re.search(r'upgradeTo', name, re.IGNORECASE): effect = "upgrade"
        elif re.search(r'mint|burn', name, re.IGNORECASE): effect = "supply"
        else: effect = "finance"
        setters.append({"function": name, "guard": guard or "none", "effect": effect})
    return setters

def oracle_mutable_caps_auditor(source: str) -> List[Dict[str, str]]:
    issues = []
    for m in re.finditer(r'require\s*\(\s*([A-Za-z_]\w*)\s*<=\s*([A-Za-z_]\w*)\s*[,)]', source):
        var, maxv = m.group(1), m.group(2)
        setter_rx = rf'(?:function\s+set\w*{re.escape(maxv)}\w*\s*\(|\b{re.escape(maxv)}\s*=\s*)'
        if re.search(setter_rx, source):
            issues.append({"var": var, "cap": maxv, "cap_is_mutable": "yes"})
    return issues

def oracle_oneblock_rug_feasibility(source: str, fee_threshold: float = None) -> Dict[str, str]:
    fee_threshold = fee_threshold or ORACLE_ONEBLOCK_FEE_THRESHOLD
    min_delay_zero = bool(re.search(r'\bminDelay\s*=\s*0\b|\bTimelockController\s*\(\s*0\s*,', source))
    has_timelock = bool(re.search(r'\bTimelockController\b', source))
    can_fee = bool(re.search(r'\bset(?:Tax|Fee|Fees?)\s*\(\s*(\d{1,6})\s*\)', source))
    can_pause = bool(re.search(r'\bpause\s*\(\s*\)', source))
    can_upgrade = bool(re.search(r'\bupgradeTo(AndCall)?\s*\(', source))
    high_fee_possible = False
    for m in re.finditer(r'\bset(?:Tax|Fee|Fees?)\s*\(\s*(\d{1,6})\s*\)', source):
        try:
            raw = int(m.group(1)); pct = _infer_percent(raw, source)
            if pct >= fee_threshold: high_fee_possible = True; break
        except: pass
    time_guard = "no_timelock" if not has_timelock else ("minDelay=0" if min_delay_zero else "delayed")
    return {
        "high_fee_same_block": "yes" if (can_fee and (time_guard in ("no_timelock","minDelay=0") and high_fee_possible)) else "no",
        "pause_same_block": "yes" if (can_pause and time_guard in ("no_timelock","minDelay=0")) else "no",
        "upgrade_same_block": "yes" if (can_upgrade and time_guard in ("no_timelock","minDelay=0")) else "no",
        "timelock_state": time_guard
    }

LOCKER_HINTS = (r'Unicrypt', r'TeamFinance', r'PinkLock', r'fluidlock', r'Lock\s*LP', r'LP\s*Locked')
def oracle_liquidity_lock_hints(source: str) -> Dict[str, str]:
    lp_to_owner = bool(re.search(DEEP_REGEX.get('lp_to_owner_addLiquidity','^$'), source, re.IGNORECASE|re.DOTALL))
    locker_hits = any(re.search(h, source, re.IGNORECASE) for h in LOCKER_HINTS)
    return {"lp_to_owner": "yes" if lp_to_owner else "no", "locker_mentions": "yes" if locker_hits else "no"}

def oracle_secret_tables(source: str) -> List[Dict[str, str]]:
    secrets = []
    for m in re.finditer(r'(?:uint\d*|bytes\d*|string)\s*\[\]\s*(?:public|private)?\s*([A-Za-z_]\w*)\s*=\s*\[([^\]]+)\];', source):
        name, content = m.group(1), m.group(2); items = re.findall(r',', content)
        if len(items) + 1 >= ORACLE_SECRET_TABLE_LEN:
            used_in_transfer = bool(re.search(rf'\b{name}\b', _get_function_body(source, "_transfer") or "", re.IGNORECASE))
            secrets.append({"name": name, "size": len(items)+1, "used_in_transfer": "yes" if used_in_transfer else "no"})
    for m in re.finditer(r'bytes(?:\d+)?\s+(?:constant\s+)?([A-Za-z_]\w*)\s*=\s*hex"([0-9a-fA-F]+)"', source):
        name, hexs = m.group(1), m.group(2)
        if len(hexs) >= ORACLE_SECRET_TABLE_LEN*2:
            used = bool(re.search(rf'\b{name}\b', source))
            secrets.append({"name": name, "size": len(hexs)//2, "used_in_transfer": "yes" if used else "no"})
    return secrets

def oracle_risk_heatmap(source: str, flags: set) -> List[Dict[str, str]]:
    heat = []
    project_funcs = extract_project_functions(source)
    for fn in project_funcs:
        body = fn["body"]; score = 0
        for f in flags:
            if re.search(re.escape(f), body, re.IGNORECASE): score += 1
        if score > 0:
            heat.append({"function": fn["name"], "from_line": fn["start_line"], "to_line": fn["end_line"], "hits": score})
    return sorted(heat, key=lambda x: x["hits"], reverse=True)[:10]

# -------- Legacy CEX detection --------
LEGACY_SOLC_4X = re.compile(r'pragma\s+solidity\s+\^?0\.(?:4)\.', re.IGNORECASE)
def detect_legacy_cex_signature(src: str) -> Dict[str, bool]:
    is_4x = bool(LEGACY_SOLC_4X.search(src))
    no_pause = not re.search(r'\bpause\s*\(', src)
    no_lists = not re.search(r'\b(blacklist|whitelist|bots)\b', src, re.IGNORECASE)
    no_proxy = not re.search(r'\b(delegatecall|upgradeTo|implementation|proxy)\b', src, re.IGNORECASE)
    no_fee = not re.search(r'(set(?:Tax|Fee)|taxFee|marketingFee|devFee)', src, re.IGNORECASE)
    full_supply_ctor = bool(re.search(
        r'constructor\s*\([^)]*\)\s*\{[\s\S]*?balances?\s*\[\s*msg\.sender\s*\]\s*(?:\+?=)\s*',
        src, re.IGNORECASE)) \
        or bool(re.search(
        r'function\s+[A-Za-z_]\w*\s*\([^)]*\)\s*(?:public|internal)?\s*\{[\s\S]*?balances?\s*\[\s*msg\.sender\s*\]\s*(?:\+?=)\s*',
        src, re.IGNORECASE))
    legacy_api = bool(re.search(r'\bapproveAndCall\b|\breceiveApproval\b', src, re.IGNORECASE))
    burn_nonstandard = bool(re.search(r'\bBurn\b', src) and not re.search(r'emit\s+Transfer\s*\([^,]+,\s*address\s*\(\s*0\s*\)\s*\)', src))
    has_manual_checks = bool(re.search(r'\brequire\s*\([^)]*[\+\-\*\/][^)]*\)', src)) or bool(re.search(r'\bassert\s*\(', src))
    signature = (is_4x and no_pause and no_lists and no_proxy and no_fee and full_supply_ctor and legacy_api)
    return {"signature": signature, "burn_nonstandard": burn_nonstandard, "manual_overflow_checks": has_manual_checks}

# -------- Reachability --------
RE_PUB = r'(public|external)'

def reachable_pause(src: str) -> bool:
    oz_way = bool(re.search(r'function\s+pause\s*\([^)]*\)\s*'+RE_PUB+r'[\s\S]*?_\s*pause\s*\(', src, re.IGNORECASE)) or \
             bool(re.search(r'function\s+unpause\s*\([^)]*\)\s*'+RE_PUB+r'[\s\S]*?_\s*unpause\s*\(', src, re.IGNORECASE))
    custom_way = bool(re.search(r'function\s+pause\s*\([^)]*\)\s*'+RE_PUB+r'[\s\S]*?\bpaused\s*=\s*true\b', src, re.IGNORECASE)) or \
                 bool(re.search(r'function\s+unpause\s*\([^)]*\)\s*'+RE_PUB+r'[\s\S]*?\bpaused\s*=\s*false\b', src, re.IGNORECASE))
    return oz_way or custom_way

def reachable_fee(src: str) -> bool:
    has_fee_vars = re.search(r'(?:tax|fee)Percent|marketingFee|devFee|liquidityFee', src, re.IGNORECASE)
    has_fee_set  = re.search(r'function\s+set\w*(Tax|Fee)[\s\S]*?'+RE_PUB+r'[\s\S]*?\{[\s\S]*?(?:tax|fee)\s*=', src, re.IGNORECASE)
    mod_in_transfer = re.search(r'function\s+_transfer\s*\([^)]*\)\s*[^{]*\{[\s\S]*?(?:tax|fee)', src, re.IGNORECASE)
    return bool(has_fee_vars and (has_fee_set or mod_in_transfer))

def reachable_upgrade(src: str) -> bool:
    has_proxy_prims = re.search(r'(ERC1967|UUPS|implementation|proxiableUUID|delegatecall|upgradeTo)', src, re.IGNORECASE)
    has_entry = re.search(r'function\s+upgrade\w*\s*\([^)]*\)\s*'+RE_PUB, src, re.IGNORECASE) or \
                re.search(r'function\s+_authorizeUpgrade\s*\([^)]*\)\s*internal', src, re.IGNORECASE)
    return bool(has_proxy_prims and has_entry)

# ==================== CIS_OFF_AURORA_v3_2.py — PART 4/5 ====================

def analyze_contract(name: str, address: str, source_code: str, contract_meta: Optional[dict]=None) -> dict:
    found_flags = set()
    explain = []   # Explain v2

    # -------- Proste flagi --------
    if re.search(r'\brequire\s*\(\s*!\s*tradingOpen', source_code, re.IGNORECASE): found_flags.add('require(!tradingOpen)')
    if re.search(r'\bblacklist\b', source_code, re.IGNORECASE): found_flags.add('blacklist')
    if re.search(r'\bwhitelist\b', source_code, re.IGNORECASE): found_flags.add('whitelist')

    # bardziej kontekstowa detekcja mint — pomijamy zwykłe helpery
    if re.search(r'\b_mint\s*\(|\b_mint\s*\(\s*(?:msg\.sender|owner|_owner)', source_code, re.IGNORECASE) \
       or re.search(r'\bfunction\s+mint\w*\s*\([^)]*\)\s*[^{]*\{', source_code, re.IGNORECASE):
        # jeśli mint występuje w funkcji konstrukcyjnej lub mint do ownera → flagujemy
        found_flags.add('mint')

    # DEX & manual drains (NIE uzależniaj od mint)
    if re.search(r'\bswap(?:Exact)?TokensForETH', source_code, re.IGNORECASE): found_flags.add('swapTokensForEth')
    if re.search(r'\bmanualSwap\b', source_code): found_flags.add('manualSwap')
    if re.search(r'\bmanualSend\b', source_code): found_flags.add('manualSend')
    if re.search(r'\bsendETHToFee\b', source_code): found_flags.add('sendETHToFee')
    if re.search(r'\bmaxTxAmount\b', source_code): found_flags.add('maxTxAmount')
    if re.search(r'\bmaxWalletSize\b', source_code): found_flags.add('maxWalletSize')
    # klasyki
    if re.search(r'pragma\s+solidity\s+(?:\^)?0\.(?:4|5|6|7)\.', source_code, re.IGNORECASE): found_flags.add('oldSolidityVersion')
    if re.search(r'\bapproveAndCall\b', source_code, re.IGNORECASE): found_flags.add('approveAndCall')
    if re.search(r'\breceiveApproval\b', source_code, re.IGNORECASE): found_flags.add('receiveApproval')
    if re.search(r'\bmultiTransfer\b', source_code, re.IGNORECASE): found_flags.add('multiTransfer')
    # miękkie AURORA
    if re.search(r'(_tax|fee|marketingFee|devFee)\s*=\s*[^;]*[\+\-\*\/]\s*[^;]*;', source_code, re.IGNORECASE): found_flags.add('dynamic_tax_expr')
    if re.search(r'if\s*\(\s*(?:block\.number|block\.timestamp)\s*<\s*\w+\s*\)\s*(?:require|revert)', source_code, re.IGNORECASE): found_flags.add('sell_limit_after_open')
    if re.search(r'if\s*\([^)]*(?:swapEnabled|swapAllowed|tradingOpen)[^)]*\)\s*\{[^}]*return\s*;', source_code, re.IGNORECASE|re.DOTALL): found_flags.add('hidden_swap_gate')
    if re.search(r'(0x[a-fA-F0-9]{40,})', source_code): found_flags.add('aurora_long_hex_string')
    if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', source_code): found_flags.add('aurora_base64_like')
    if re.search(r'\b(?:_[0-9a-f]{8,}|hexString|encodedSource|obf|scramble|_xor)\b', source_code, re.IGNORECASE): found_flags.add('aurora_obfusk_var')
    if re.search(r'>>\s*\d+|<<\s*\d+', source_code): found_flags.add('aurora_large_bitshift')
    if re.search(r'(?:\b\d{6,}\b.*){3,}', source_code): found_flags.add('aurora_many_numeric_literals')
    ids = re.findall(r'\b[A-Za-z_][A-Za-z0-9_]{2,}\b', source_code)
    comments = len(re.findall(r'//|/\*', source_code))
    if len(set(ids)) >= 2000 and comments < max(1, len(source_code.splitlines()) * 0.005):
        found_flags.add('aurora_minified_like')

    # „Miękkie” wykrycie obecności mechaniki fee/tax (dla kategorii)
    if re.search(r'\bset(?:Tax|Fee|Fees?)\b', source_code, re.IGNORECASE): found_flags.add('setTax')
    if re.search(r'\bupdateFee\b', source_code, re.IGNORECASE):           found_flags.add('updateFee')
    if re.search(r'\btaxFee\b', source_code, re.IGNORECASE):               found_flags.add('taxFee')
    if re.search(r'\bmarketingFee\b', source_code, re.IGNORECASE):         found_flags.add('marketingFee')
    if re.search(r'\bdevFee\b', source_code, re.IGNORECASE):               found_flags.add('devFee')

    # High tax
    high_taxes = detect_high_tax_over_25(source_code)
    if high_taxes:
        found_flags.add('highTaxOver25')
        explain.append("HighTax≥25: twarde progi w zmiennych/setterach.")

    # Tri
    tri = _supermetrics_detect_three(source_code)
    for k in ('mint100_owner','oz_import','big_supply_1e9'):
        if tri.get(k): found_flags.add(k)

    # DeepFusion
    for key, rx in DEEP_REGEX.items():
        if re.search(rx, source_code, re.IGNORECASE | re.DOTALL):
            found_flags.add(key)    # --- PATCH #33: mikro-detekcje (diagnostyczne, bez zmiany wag) ---
    # 1) constructor-mint do parametru (treasury/vesting) — łagodzimy wnioski ręcznie
    if re.search(r'constructor\s*\([^)]*\)\s*\{[\s\S]*?_mint\s*\(\s*[A-Za-z0-9_]+\s*,', source_code, re.IGNORECASE):
        found_flags.add('ctor_mint_param')
        explain.append("Constructor mint (parametr) → możliwy treasury/vesting init (diagnostic).")

    # 2) przypisanie całej podaży do deployera w konstruktorze (prosty ERC20)
    if re.search(r'constructor\s*\([^)]*\)\s*\{[\s\S]*?balances?\s*\[\s*msg\.sender\s*\]\s*(?:=|\+?=)\s*\d', source_code, re.IGNORECASE):
        found_flags.add('ctor_assign_full_supply_to_deployer')
        explain.append("Constructor assigns full/large supply to deployer — centralization risk (diagnostic).")

    # 3) renounceOwnership, które nie ustawia owner=address(0)
    if re.search(r'function\s+renounceOwnership\s*\([^)]*\)\s*(?:public|external|internal)?\s*\{[\s\S]*?\}', source_code, re.IGNORECASE) \
       and not re.search(r'owner\s*=\s*address\s*\(\s*0\s*\)', source_code, re.IGNORECASE):
        found_flags.add('fake_renounce')
        explain.append("RenounceOwnership nie ustawia owner=0x0 → podejrzane (fake_renounce).")

    # 4) burn, które realnie winduje saldo ownera / manipuluje totalSupply
    if re.search(r'function\s+burn\s*\([^)]*\)\s*\{[\s\S]*?(?:_balances?\s*\[[^\]]+\]\s*=\s*(?:_totalSupply|0))[\s\S]*?(?:owner\s*\(|owner\b)', source_code, re.IGNORECASE):
        found_flags.add('fake_burn_to_owner')
        explain.append("Burn manipuluje saldami i referuje ownera → podejrzany mint/drain (diagnostic).")

    # 5) symulacja „sprzedaży” eventem emit Transfer(..., pair, 1)
    if re.search(r'emit\s+Transfer\s*\(\s*\w+\s*,\s*(?:uniswapV2Pair|pair)\s*,\s*1\s*\)\s*;', source_code, re.IGNORECASE):
        found_flags.add('fake_sell_event')
        explain.append("Emit Transfer(..., pair, 1) — podejrzana symulacja sprzedaży (diagnostic).")
    # --- koniec PATCH #33 ---


    # ---- PATCH 6: Kill-Switch detection (v1/v2) ----
    kill_switch = False
    ks_hits = []
    try:
        for k, rx in KILLSWITCH_RE.items():
            if rx.search(source_code):
                ks_hits.append(k)
        for k, rx in KS2_RE.items():
            if rx.search(source_code):
                ks_hits.append(f"KS2:{k}")
    except Exception:
        ks_hits = ks_hits  # defensive — nic

    if ks_hits:
        kill_switch = True
        found_flags.add('kill_switch')
        explain.append("Kill-Switch gates: " + ", ".join(sorted(set(ks_hits))) + ".")


    lz_stack = is_layerzero_stack(source_code)
    if lz_stack:
        for fp in ['generic_send_fee_wallet_in_body', 'generic_suspicious_fn_name']:
            if fp in found_flags:
                found_flags.remove(fp)
                explain.append("LZ/OFT whitelist: zneutralizowano ogólne podejrzenia 'send/fee/wallet' w cross-chain.")

    # Fee taint + tax_no_cap
    fee_flow = fee_taint_analysis(source_code)
    has_cap_guard = any(f["guarded_cap"] == "yes" for f in fee_flow["flows"])
    has_drain = any(re.search(rf'\b{sink}\b', source_code) for sink in ['manualSend','sendETHToFee'])
    if (re.search(r'(taxFee|marketingFee|devFee|setTax|setFees|updateFee)', source_code, re.IGNORECASE) and
        not re.search(r'\b(maxSupply|cap)\b', source_code, re.IGNORECASE)):
        found_flags.add('tax_no_cap')
        explain.append("tax_no_cap: są podatki/fee bez twardego capu.")

    # Market & Rug
    market_matrix = build_market_matrix(source_code)
    rug_dist = rug_distance(source_code)

    # Legacy CEX capture (przywrócone)
    legacy = detect_legacy_cex_signature(source_code)
    if legacy["signature"]:
        found_flags.add('legacy_cex_signature'); explain.append("Legacy CEX sygnatura: stary szablon CEX/treasury.")
    if legacy["burn_nonstandard"]:
        found_flags.add('burn_nonstandard'); explain.append("Burn nonstandard: brak Transfer(...,0x0).")
    if legacy["manual_overflow_checks"]:
        found_flags.add('manual_overflow_checks'); explain.append("Manualne overflow-checki (0.4.x).")

    # Reachability
    reach = {
        "pause":   reachable_pause(source_code),
        "fee":     reachable_fee(source_code),
        "upgrade": reachable_upgrade(source_code),
    }
    if reach["pause"]:
        found_flags.add('pause'); explain.append("Pauza osiągalna: public/external entry → _pause/_unpause.")
    if reach["upgrade"]:
        if re.search(r'\bdelegatecall\b', source_code, re.IGNORECASE): found_flags.add('delegatecall')
        if re.search(r'\bupgradeTo\b', source_code): found_flags.add('upgradeTo')
        if re.search(r'\bimplementation\b', source_code): found_flags.add('implementation')
        if re.search(r'\b(ERC1967|UUPS|proxy)\b', source_code, re.IGNORECASE): found_flags.add('proxy')
        explain.append("Upgrade reachable: public/external entry (lub UUPS authorize).")
    if not reach["pause"] and re.search(r'\bPausable\b', source_code, re.IGNORECASE):
        explain.append("Pausable import bez expose → not_reachable (bez kary).")
    if not reach["upgrade"] and re.search(r'(ERC1967|UUPS)', source_code, re.IGNORECASE):
        explain.append("Proxy/upgrade prymy bez public entry → not_reachable (bez kary).")

    # Vanilla OZ uplift (przywrócony)
    vanilla_uplift = 0.0
    if 'oz_import' in tri and not reach["pause"] and not reach["fee"] and not reach["upgrade"] and not any(
        x in found_flags for x in ('delegatecall','upgradeTo','implementation','proxy','highTaxOver25','mint100_owner')
    ):
        vanilla_uplift = max(0.0, float(VANILLA_OZ_UPLIFT))
        explain.append(f"Plain OZ ERC-20 (single mint) → vanilla boost +{vanilla_uplift:.2f}.")

    # PATCH #29 — Router Exception + TaxCapSoftening
    router_exception = False
    if ROUTER_EXCEPTION_ON and (is_trusted_router_context(source_code) or has_router_instance(source_code) or KNOWN_ROUTERS_RX.search(source_code)):
        router_exception = True
        found_flags.add('router_exception')
        explain.append("Router Exception: wykryto znany DEX Router → neutralizacja skimmer FP.")

    tax_any = detect_any_tax_settings(source_code)
    tax_softener = False
    if TAX_SOFTENING_ON:
        has_low_tax = any(pct <= 25.0 for _, pct in tax_any)
        has_caps_kw = bool(re.search(r'\b(maxTxAmount|maxWallet(Size)?|feeCap|_maxFee|_maxTax)\b', source_code, re.IGNORECASE))
        if (has_low_tax or has_caps_kw) and not high_taxes:
            tax_softener = True
            explain.append("TaxCapSoftening: tax ≤25% lub fee-cap → maks. kara kategorii podatków −2.")

    # -------- Scoring --------
    # [PATCH31] Governance context
    gov_ctx = {
        "timelock": detect_timelock(source_code),
        "multisig": detect_multisig(source_code),
        "proxyadmin": detect_proxy_admin(source_code),
        "governor": detect_governor(source_code)
    }

    pred_reasons, pred_raw = [], 0
    if 'require(!tradingOpen)' in found_flags: pred_raw += 10; pred_reasons.append("require(!tradingOpen) (+10)")
    if 'pause' in found_flags: pred_raw += 10; pred_reasons.append("pause (+10)")
    # PATCH 6 — Kill-Switch penalty (v1/v2)
    if 'kill_switch' in found_flags:
        ks_penalty_val = 12 if os.getenv("AURORA_KILLSWITCH_STRICT","OFF").upper()=="ON" else 8
        pred_raw += ks_penalty_val
        pred_reasons.append(f"KILL-SWITCH (+{ks_penalty_val})")

    if {'delegatecall','upgradeTo','implementation','proxy'} & found_flags:
        proxy_penalty = 10
        if gov_ctx["timelock"] or gov_ctx["multisig"] or gov_ctx["proxyadmin"] or gov_ctx["governor"]:
            proxy_penalty = 5
            explain.append("Proxy/upgrade pod governance (timelock/multisig/proxyadmin) → łagodniejsza kara.")
        pred_raw += proxy_penalty
        pred_reasons.append(f"proxy/upgrade (+{proxy_penalty})")
    if 'highTaxOver25' in found_flags: pred_raw += 12; pred_reasons.append("highTaxOver25 (+12)")
    if 'mint100_owner' in found_flags: pred_raw += 12; pred_reasons.append("mint100_owner (+12)")
    d_candidates = [f for f in [
        'dynamic_tax_expr','hidden_swap_gate','sell_limit_after_open','tax_no_cap',
        'aurora_long_hex_string','aurora_base64_like','aurora_obfusk_var',
        'aurora_large_bitshift','aurora_many_numeric_literals','aurora_minified_like'
    ] if f in found_flags]
    d_full_used = 0
    for f in d_candidates:
        w = weight_D(f, guarded_cap=has_cap_guard, has_drain=has_drain)
        add = w if d_full_used < AURORA_D_MAX_FULL else AURORA_D_SOFT
        pred_raw += add; pred_reasons.append(f"{f} (+{add})")
        if d_full_used < AURORA_D_MAX_FULL: d_full_used += 1
    pred_raw = min(100, pred_raw)

    # Kategorie i base score
    overview_lines, triggered_categories, raw_score = [], [], 0
    for cat, flags in categories.items():
        hit = any(ff in found_flags for ff in flags)
        if REPORT_MODE.upper()=="BRIEF" and LEGACY_MODE!="ON" and "Legacy CEX" in cat:
            hit = False
        overview_lines.append(f"• {cat}: {'TAK' if hit else 'NIE'}")
        if hit: raw_score += category_weights[cat]; triggered_categories.append(cat)

    # Router Exception neutralizacja skimmera
    if router_exception and "Skimmer ETH / drenaż do tax walleta" in triggered_categories:
        raw_score -= category_weights["Skimmer ETH / drenaż do tax walleta"]
        explain.append("Router Exception: odjęto wagę kategorii 'Skimmer ETH...' (FP neutralized).")

    # [PATCH31] LZ/OFT: nie penalizuj kategorii 'Skimmer...' przy LZ stack
    if lz_stack and "Skimmer ETH / drenaż do tax walleta" in triggered_categories:
        raw_score -= category_weights["Skimmer ETH / drenaż do tax walleta"]
        explain.append("LZ/OFT whitelist: zdjęto karę za 'Skimmer ETH ...' (cross-chain flow ≠ drain).")

    # Tax softening do −2 (gdy <=25%/cap) i brak highTaxOver25
    if tax_softener and "Wykryto wysokie podatki lub opłaty" in triggered_categories and "highTaxOver25" not in found_flags:
        raw_score -= max(0, category_weights["Wykryto wysokie podatki lub opłaty"] - 2)

    # Normalizacja + vanilla uplift
    max_score = sum(category_weights.values()) + 12
    normalized_score = round(10 - (raw_score / max_score) * 10, 2)
    final_score = round(max(0.0, normalized_score) - (pred_raw/10.0) + vanilla_uplift, 2)

    # DAO-Uplift
    def compute_dao_uplift(src: str, found_flags: set) -> Tuple[int, List[str]]:
        notes = []
        red_flags = {'eth_skimmer_on_sell','allowance_bypass_tax_wallet','balance_wipe_swap','fake_burn_mint_to_addr',
                     'dead_to_zero_swap','silent_drop_no_event','require(!tradingOpen)','blacklist'}
        if any(r in found_flags for r in red_flags):
            notes.append("DAO-Uplift: zablokowany (red flags obecne).")
            return 0, notes
        gov = 0
        if re.search(r'\bTimelockController\b|\bTIMELOCK_ROLE\b', src, re.IGNORECASE): gov += 1; notes.append("TimelockController detected (+1).")
        if re.search(r'\bGovernor\b|\bGovernorVotes\b', src, re.IGNORECASE): gov += 2; notes.append("Governor detected (+2).")
        if gov > 3: gov = 3
        if gov == 0: notes.append("DAO-Uplift: brak timelock/governor.")
        return gov, notes

    dao_bonus, dao_notes = compute_dao_uplift(source_code, found_flags)
    if dao_bonus > 0:
        final_score = round(final_score + min(DAO_UPLIFT_MAX, dao_bonus), 2)
        explain.append(f"DAO-Uplift: +{dao_bonus} za Timelock/Governor.")
    explain.extend(dao_notes)    # ---- PATCH 4/4a: Owner-Controlled Advisory + clamp 6.5 ----
    owner_control = ('mint100_owner' in found_flags)
    clean_code = not any(x in found_flags for x in [
        'highTaxOver25','blacklist','whitelist','pause','delegatecall','upgradeTo','implementation','proxy',
        'sell_limit_after_open','hidden_swap_gate','tax_no_cap'
    ])

    # clamp: „czysta centralizacja” nie spada poniżej 6.5
    if owner_control and clean_code and final_score < 6.5:
        final_score = 6.5

    # okno advisory 6.5–7.5
    advisory = None
    if owner_control and clean_code and 6.5 <= final_score <= 7.5:
        advisory = {
            "label": "Owner-Controlled Advisory",
            "candidate": True,
            "reason": "100% supply u deployera; brak bramek/fee — ryzyko decyzji człowieka (LP/governance)."
        }
        explain.append("ADVISORY: Duża kontrola właściciela (6.5–7.5) — sprawdź LP lock / governance / maxSupply.")


    # Good snap + cap 8.8
    if GOOD_SNAP_MIN <= final_score < 8.0: final_score = 8.0
    if final_score > DAO_GOOD_CAP: final_score = DAO_GOOD_CAP

    # Identity (PATCH #30)
    ident = resolve_identity(source_code)

    # [PATCH31] Blue-chip floor po labelingu/adresie (przy PASS matrix)
    BLUECHIP_ADDR_FLOOR = {
        "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9": 6.5,  # AAVE
        "0x152649ea73beab28c5b49b26eb48f7ead6d4c898": 6.0,  # CAKE (OFT/LZ)
    }
    addr_l = (address or "").lower()
    if (addr_l in BLUECHIP_ADDR_FLOOR) and all(v == "PASS" for v in market_matrix.values()):
        if final_score < BLUECHIP_ADDR_FLOOR[addr_l]:
            explain.append(f"Blue-chip floor: podniesiono wynik do {BLUECHIP_ADDR_FLOOR[addr_l]:.2f}.")
            final_score = BLUECHIP_ADDR_FLOOR[addr_l]

    # Risk label
    risk_level = ("BEZPIECZNY" if final_score >= 8 else ("RYZYKOWNY" if final_score >= 5 else "EKSTREMALNE RYZYKO")) + f" ({final_score}/10)"
    proxy_root_cause = ('proxy' in found_flags or 'upgradeTo' in found_flags or 'implementation' in found_flags or 'delegatecall' in found_flags)
    if final_score < 5 and proxy_root_cause and all(v == "PASS" for v in market_matrix.values()) and \
       (gov_ctx["timelock"] or gov_ctx["multisig"] or gov_ctx["proxyadmin"] or gov_ctx["governor"]):
        risk_level = "GOV-UPGRADABLE (review)"

    # --- v3.3 Strict Investor UX — decyzja GO/REVIEW/NO-GO + checklista + confidence ---
    red_flags = {
        'require(!tradingOpen)', 'blacklist', 'eth_skimmer_on_sell', 'allowance_bypass_tax_wallet'
    }
    proxy_set = {'delegatecall','upgradeTo','implementation','proxy'}
    matrix_all_pass = all(v == "PASS" for v in market_matrix.values())
    has_red = any(r in found_flags for r in red_flags)
    proxy_no_gov = (proxy_set & found_flags) and not (gov_ctx["timelock"] or gov_ctx["multisig"] or gov_ctx["proxyadmin"] or gov_ctx["governor"])
    high_tax = ('highTaxOver25' in found_flags)

    if (final_score < 5) or (not matrix_all_pass) or has_red or proxy_no_gov or high_tax:
        decision = "NO-GO"
    elif (final_score >= 8) and (matrix_all_pass) and (not has_red) and (not proxy_no_gov) and (not high_tax):
        decision = "GO"
    else:
        decision = "REVIEW"

    # Checklista 20s — krótkie, konkretne punkty do klikania w explorerze
    checklist = []
    if proxy_set & found_flags:
        checklist.append("Sprawdź admina proxy + czy istnieje timelock/proxyadmin (EIP-1967).")
    if 'tax_no_cap' in found_flags or 'mint' in found_flags:
        checklist.append("Zweryfikuj maxSupply/cap oraz politykę mint (brak rozwodnienia bez limitu).")
    if 'pause' in found_flags or 'require(!tradingOpen)' in found_flags:
        checklist.append("Sprawdź politykę otwarcia/pauzy (kto, kiedy i na jak długo).")
    if 'lp_to_owner_addLiquidity' in found_flags:
        checklist.append("Potwierdź LP lock (TeamFinance/Unicrypt/PinkLock) — link do transakcji.")
    if 'highTaxOver25' in found_flags or any(x in found_flags for x in ('setTax','updateFee','taxFee','marketingFee','devFee')):
        checklist.append("Zweryfikuj realne fee na łańcuchu (≤25% po deployu, brak ukrytych podbić).")
    if not checklist:
        checklist.append("Zweryfikuj podstawy: timelock/multisig, fee, cap, LP lock, proxy admin.")

    # Confidence index — siła diagnozy vs neutralizacje
    triggered_count = len(triggered_categories)
    neutralizations = []
    if 'router_exception' in found_flags:
        neutralizations.append("RouterException")
    if lz_stack:
        neutralizations.append("LZ/OFT-whitelist")
    if tax_softener:
        neutralizations.append("TaxCapSoftening")
    conf_score = max(0, min(10, triggered_count + len(d_candidates) + (1 if 'highTaxOver25' in found_flags else 0) - len(neutralizations)))
    conf_level = "HIGH" if conf_score >= 7 else ("MED" if conf_score >= 4 else "LOW")

    # Proof-packs (skrót + Oracle)
    proof_packs = []
    if market_matrix.get("SELL(user→pair)", "").startswith("FAIL"):
        proof_packs.append({"claim": "SELL blocked", "reason": market_matrix["SELL(user→pair)"]})
    if 'tax_no_cap' in found_flags:
        proof_packs.append({"claim": "Tax w/out cap", "reason": "no maxSupply/cap; drains? " + ("yes" if has_drain else "no")})
    for flow in fee_flow["flows"][:4]:
        proof_packs.append({"claim":"fee_flow", "var": flow["var"], "sinks": flow["sinks"], "guarded_cap": flow["guarded_cap"], "expr": flow["expr"]})

    ownership_surface = oracle_ownership_surface(source_code)
    mutable_caps = oracle_mutable_caps_auditor(source_code)
    oneblock = oracle_oneblock_rug_feasibility(source_code, ORACLE_ONEBLOCK_FEE_THRESHOLD)
    lock_hints = oracle_liquidity_lock_hints(source_code)
    secret_tabs = oracle_secret_tables(source_code)
    heatmap = oracle_risk_heatmap(source_code, found_flags)
    if oneblock.get("high_fee_same_block") == "yes":
        proof_packs.append({"claim":"one_block_high_fee","reason":f"timelock={oneblock['timelock_state']}, setFee≥{ORACLE_ONEBLOCK_FEE_THRESHOLD}%"} )
    if oneblock.get("upgrade_same_block") == "yes":
        proof_packs.append({"claim":"one_block_upgrade","reason":f"timelock={oneblock['timelock_state']}"} )
    for cap in mutable_caps[:3]:
        proof_packs.append({"claim":"mutable_cap", "var":cap["var"], "cap":cap["cap"], "mutable":"yes"})
    if lock_hints["lp_to_owner"] == "yes" and lock_hints["locker_mentions"] == "no":
        proof_packs.append({"claim":"lp_owner_no_lock_hints","reason":"LP→owner & brak wzmianki o lockerze"})

    threats = []
    for cat in triggered_categories: threats.append(f"- {cat}")
    for f in sorted(found_flags): threats.append(f"- {f}: {flag_explanations.get(f, '')}")
    if high_taxes:
        threats.append("🚨 High taxes/opłaty (≥25%): " + ", ".join([f"{v}~{p:.1f}%" for v,p in high_taxes]))

    # BRIEF/VERBOSE
    if REPORT_MODE.upper() == "BRIEF":
        report_threats = threats[:EVIDENCE_BUDGET]
        report_proofs  = proof_packs[:EVIDENCE_BUDGET]
        report_explain = explain[:EVIDENCE_BUDGET]
    else:
        report_threats = threats
        report_proofs  = proof_packs
        report_explain = explain

    # [PATCH31] preferuj label z kontraktu jako nazwa
    ident = ident  # alias
    token_name = (ident.get("resolved_name") or name or "Contract").strip()

    report = {
        "version": "v3.3",
        "name": token_name,
        "address": address,
        "score": final_score,
        "decision": decision,
        "checklist": checklist,
        "confidence": {"score": conf_score, "level": conf_level, "neutralizations": neutralizations},
        "risk_level": risk_level,
        "pred": {"raw": pred_raw, "norm": round((pred_raw/100.0)*10.0,2), "reasons": pred_reasons},
        "overview": overview_lines,
        "explain": report_explain,
        "threats": report_threats,
        "market_matrix": market_matrix,
        "governance_rug_distance": rug_dist,
        "fee_flow_proofs": fee_flow["flows"],
        "proof_packs": report_proofs,
        "oracle": {
            "ownership_surface": ownership_surface,
            "mutable_caps": mutable_caps,
            "one_block": oneblock,
            "liquidity_lock_hints": lock_hints,
            "secret_tables": secret_tabs,
            "risk_heatmap": heatmap
        },
        "identity": ident,
        "advisory": advisory,
        "policy": {
            "REPORT_MODE": REPORT_MODE,
            "EVIDENCE_BUDGET": EVIDENCE_BUDGET,
            "GOOD_SNAP_MIN": GOOD_SNAP_MIN,
            "DAO_UPLIFT_MAX": DAO_UPLIFT_MAX,
            "DAO_GOOD_CAP": DAO_GOOD_CAP,
            "LEGACY_MODE": LEGACY_MODE,
            "AURORA_D_MAX_FULL": AURORA_D_MAX_FULL,
            "AURORA_D_SOFT": AURORA_D_SOFT
        }
    }
    return report

# ==================== CIS_OFF_AURORA_v3_2.py — PART 5/5 ====================

# -------- I/O & CLI --------
def fetch_contract_source(address: str) -> Optional[str]:
    try:
        url = "https://api.etherscan.io/v2/api"
        params = {"chainid":"1","module":"contract","action":"getsourcecode","address":address,"apikey":ETHERSCAN_API_KEY}
        r = requests.get(url, params=params, timeout=20)
        if r.status_code != 200: log_err(f"Etherscan V2 HTTP {r.status_code}"); return None
        data = r.json()
        if not data or data.get("status") != "1" or not data.get("result"): log_err("Etherscan V2: brak kodu (status!=1)"); return None
        result = data["result"][0]
        source_code = result.get("SourceCode") or ""
        # Multi-file flatten (Etherscan "{{...}}") — try two parsers + fallback
        if source_code.startswith("{{") and source_code.endswith("}}"):
            j = None
            try:
                j = json.loads(source_code[1:-1])  # zdejmij po 1 klamrze
            except Exception:
                try:
                    j = json.loads(source_code.strip("{}"))
                except Exception:
                    j = None
            if isinstance(j, dict) and "sources" in j:
                parts = []
                for path, meta in j["sources"].items():
                    content = (meta.get("content") or "")
                    parts.append(f"\n// ---- {path} ----\n{content}")
                source_code = "\n".join(parts)
        return source_code
    except Exception as e:
        log_err(f"Etherscan error: {e}"); return None

def _rotate_path(base_dir: str, base_name: str) -> str:
    idx = 1
    while True:
        fpath = os.path.join(base_dir, f"{base_name}.json") if idx == 1 else os.path.join(base_dir, f"{idx}{base_name}.json")
        if not os.path.exists(fpath): return fpath
        try:
            with open(fpath, "r", encoding="utf-8") as f: data = json.load(f)
            if isinstance(data, list) and len(data) < ROTATION_LIMIT: return fpath
        except: pass
        idx += 1

def _append_json(file_path: str, entry: dict):
    data = []
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f: data = json.load(f)
            if not isinstance(data, list): data = []
        except: data = []
    data.append(entry)
    with open(file_path, "w", encoding="utf-8") as f: json.dump(data, f, ensure_ascii=False, indent=2)

def _append_txt(file_path: str, line: str):
    with open(file_path, "a", encoding="utf-8") as f: f.write(line.rstrip() + "\n")

def _append_csv(file_path: str, header: list, row: list):
    need_header = not os.path.exists(file_path) or os.path.getsize(file_path) == 0
    with open(file_path, "a", encoding="utf-8") as f:
        if need_header: f.write(",".join(header) + "\n")
        # prosty escaping przecinków w checklist
        row = [str(x).replace("\n"," ").replace(",",";") for x in row]
        f.write(",".join(row) + "\n")

def save_report(report: dict):
    score = report["score"]
    if score >= 8.0: out_dir, label = ANALYZE_DIRS["good"], "GOOD"
    elif score >= 6.5: out_dir, label = ANALYZE_DIRS["risk"], "RISK"
    else: out_dir, label = ANALYZE_DIRS["extreme_risk"], "EXTREME_RISK"

    # JSON (bez zmian) — już zawiera decision/checklist/confidence
    json_path = _rotate_path(out_dir, label.lower()); _append_json(json_path, report)

    # TXT — zachowaj stary 4-kolumnowy wiersz + dodaj 2. linię z user-view (niełamliwie)
    token_name = (report.get("identity", {}).get("resolved_name") or report.get("name") or "Contract").strip()
    txt_path = json_path.replace(".json", ".txt")
    _append_txt(txt_path, f"{token_name},{report['address']},{report['score']:.2f},{label}")
    # nowa, pomocnicza linia do tego samego TXT
    decision = report.get("decision","REVIEW")
    conf = report.get("confidence",{})
    conf_lvl, conf_sc = conf.get("level","MED"), conf.get("score","-")
    ch = report.get("checklist", [])[:3]  # top-3 do TXT
    _append_txt(txt_path, f"# UX: decision={decision} | confidence={conf_lvl}({conf_sc}/10) | checklist: " + " | ".join(ch))

    # MAILER CSV — wygodny do zaciągania przez CMO
    mailer_csv = os.path.join(out_dir, "mailer.csv")
    adv_flag = "YES" if (report.get("advisory") or {}).get("candidate") else ""
    header = ["name","address","score","bucket","advisory","decision","confidence_level","confidence_score","check1","check2","check3"]
    row = [token_name, report['address'], f"{report['score']:.2f}", label, adv_flag, decision, conf_lvl, str(conf_sc), ch[0] if len(ch)>0 else "", ch[1] if len(ch)>1 else "", ch[2] if len(ch)>2 else ""]

    _append_csv(mailer_csv, header, row)

    log_ok(f"Zapisano: {token_name},{report['address']},{report['score']:.2f},{label}")
    return json_path, txt_path

def run_console():
    print(BANNER)
    while True:
        try: s = input("Adresy (CSV) lub 'help'/'exit': ").strip()
        except (EOFError, KeyboardInterrupt): print(); break
        if not s: continue
        if s.lower() in {"exit","quit","q"}: break
        if s.lower() == "help":
            print("• Podaj adresy 0x... rozdzielone przecinkami; opcjonalnie Nazwa:0x...")
            print("• ENV: GOOD_SNAP_MIN, AURORA_(D_MAX_FULL|D_SOFT|LEGACY_MODE|ROUTER_EXCEPTION|TAX_SOFTENING)")
            continue

        addrs = [x.strip() for x in s.split(",") if x.strip()]
        results, t0 = [], time.time()
        for item in addrs:
            if ":" in item: name, addr = item.split(":", 1); name, addr = name.strip(), addr.strip()
            else: name, addr = "Contract", item
            if not re.match(r"^0x[a-fA-F0-9]{40}$", addr): log_warn(f"Zły adres: {addr}"); continue

            src = fetch_contract_source(addr)
            if not src: log_err(f"Brak źródła dla {addr}"); continue

            path = os.path.join(CONTRACTS_DIR, f"{addr.lower()}_{_slugify(name)}.json")
            with open(path, "w", encoding="utf-8") as f: json.dump({"address": addr, "name": name, "source_code": src}, f, ensure_ascii=False, indent=2)
            log_ok(f"Zapisano źródło: {path}")

            report = analyze_contract(name, addr, src)
            results.append(report); save_report(report)

            mm = report.get("market_matrix", {})
            log_info(f"MATRIX: SELL={mm.get('SELL(user→pair)')} | BUY={mm.get('BUY(pair→user)')} | P2P={mm.get('P2P(user→user)')}")
            ident = report.get("identity", {})
            disp_name = (report.get("name") or ident.get("resolved_name") or "Contract")
            if ident.get("resolved_name") or ident.get("resolved_symbol"):
                log_info(f"LABEL: {disp_name} ({ident.get('resolved_symbol','?')}) | proxy={ident.get('is_proxy')} | conf={ident.get('name_confidence')}")
            adv = report.get("advisory") or {}
            if adv.get("candidate"):
                log_warn("ADVISORY: Duża kontrola Właściciela (6.5–7.5) — ręczna weryfikacja LP/governance zalecana.")

            # v3.3 — decyzja i confidence
            log_info(f"DECISION: {report.get('decision','REVIEW')} | confidence={report.get('confidence',{}).get('level','MED')}({report.get('confidence',{}).get('score','-')}/10)")
            if AURORA_MODE == "BEGINNER":
                ch = report.get('checklist', [])[:3]
                for i, item in enumerate(ch, 1):
                    log_info(f"CHECK{i}: {item}")
            gd = report.get("governance_rug_distance", {})
            log_info(f"RUG_DISTANCE: set_fee_99→{gd.get('set_fee_99',{}).get('min_txs','-')} tx; "
                     f"pause_market→{gd.get('pause_market',{}).get('min_txs','-')} tx; "
                     f"upgrade_impl→{gd.get('upgrade_impl',{}).get('min_txs','-')} tx")

        dt = time.time() - t0
        if results:
            print("-"*80)
            print(f"SUMMARY: analyzed={len(results)} | GOOD={sum(1 for r in results if r['score']>=8)} | "
                  f"RISK={sum(1 for r in results if 5<=r['score']<8)} | EXTREME={sum(1 for r in results if r['score']<5)} | "
                  f"avg={sum(r['score'] for r in results)/len(results):.2f} | time={dt:.2f}s")
            print("WORST (top5):")
            for r in sorted(results, key=lambda r: r["score"])[:5]:
                label = "good" if r["score"]>=8 else ("risk" if r["score"]>=5 else "extreme_risk")
                print(f"  • {r['name']} ({r['address']}) → {r['score']:.2f}/10 → {label}")
            print("-"*80)

def server_single_address(address: str) -> int:
    # Validate address
    if not re.match(r"^0x[a-fA-F0-9]{40}$", address):
        log_err(f"Invalid ETH address: {address}")
        return 2

    src = fetch_contract_source(address)
    if not src:
        log_err(f"Brak źródła dla {address}")
        return 3

    name = "Contract"
    path = os.path.join(CONTRACTS_DIR, f"{address.lower()}_{_slugify(name)}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"address": address, "name": name, "source_code": src}, f, ensure_ascii=False, indent=2)
    log_ok(f"Zapisano źródło: {path}")

    report = analyze_contract(name, address, src)
    save_report(report)

    mm = report.get("market_matrix", {})
    log_info(f"MATRIX: SELL={mm.get('SELL(user→pair)')} | BUY={mm.get('BUY(pair→user)')} | P2P={mm.get('P2P(user→user)')}")
    return 0

def main():
    parser = argparse.ArgumentParser(description="CIS OFF — AURORA v3.3 (NEXUS) — CIS Integrated+")
    parser.add_argument("--repl", action="store_true", help="tryb interaktywny (konsola)")
    parser.add_argument("--address", help="pojedynczy adres 0x... dla trybu serwerowego")
    args = parser.parse_args()

    if args.address:
        code = server_single_address(args.address)
        raise SystemExit(code)
    else:
        run_console()

if __name__ == "__main__":
    main()
# ==================== END — PART 5/5 ====================
