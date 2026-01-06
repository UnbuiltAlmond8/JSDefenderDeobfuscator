import json
import re
import subprocess
import sys

try:
    import requests
    from getpass import getpass
    from simpleeval import simple_eval
except ImportError:
    print("[!] Missing dependencies.")
    print("[!] Required: requests, getpass, simpleeval")
    exit()

VARIABLE_NAME_REGEX = VNR = r"""[
    _                       # For hexadecimal and sequential mode
    a-z                     # For Base62
    A-Z
    0-9                     # For Base62
    \u16A0-\u16FF           # For Runic
    \u2C00-\u2C5F           # For Glagolitic
    \U0001E000-\U0001E02F   # Had to use extended sequence to avoid malformed range
    \u2D30-\u2D7F           # For Tifinagh
]"""

def unflatten(js_code):
    OFFER = input("\n[*] Want to rename variables and unflatten the control flow? (yes/no) ")
    if OFFER.startswith("y"):
        comments = input("[*] Add comments? (yes/no) ").startswith("y")
    else:
        print("[!] Control flow may not have been unflattened.")
        print("[!] Variables have not been renamed.")
        return

    API_KEY = getpass("Google Gemini API Key: ")
    if not API_KEY:
        print('[!] Error unflattening, API key was not provided.')
        return
    
    USER_INPUT = f"""
Rename the variables, simplify expressions, and unflatten the control flow of this JavaScript script.
Wrap the resulting code in a javascript code block.
Remember to include any simplified expressions directly in the script in place of obfuscated expressions.

```javascript
{js_code}
```

{'Avoid inserting any comments unless next to function definitions that may be confusing.' 
    if not comments else 
 'Insert comments where important, but not excessively.'}.
"""

    print("[*] Renaming variables and unflattening the control flow...")

    response = requests.post(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent",
        headers={
            'x-goog-api-key': API_KEY
        },
        json={
            "contents": [{
                "parts": [{"text": USER_INPUT}]
            }]
        },
        stream=False
    )

    try:
        response.raise_for_status()
    except requests.HTTPError:
        print("[!] Error unflattening, something went wrong with the response.")
        return

    model_response = response.json()
    try:
        model_response = model_response['candidates'][0]['content']['parts'][0]['text']
    except (KeyError, ValueError, IndexError):
        print('[!] Error unflattening, something went wrong with the response.')
        return

    try:
        code_begin = model_response.split("```javascript")[1]
        code = code_begin.split("```")[0]
    except:
        print("[!] Error unflattening, malformed response.")
        return  
    
    print("[*] Successfully renamed variables and unflattened the control flow.\n")
    print(code)
    
def simplify(js_code):
    # A. MATH PATTERNS
    # Matches Hex, Octal, Decimal
    num_pattern = r'(?:0[xX][0-9a-fA-F]+|0[oO][0-7]+|0[0-7]*|[1-9]\d*|0)'
    op_pattern = r'(?:>>>|<<|>>|[-+*/%&|^])'
    # Group 1: Left, Group 2: Op, Group 3: Right
    math_regex = re.compile(fr'({num_pattern})\s*({op_pattern})\s*({num_pattern})')
    paren_regex = re.compile(fr'(?<![\w$])\(\s*({num_pattern})\s*\)(?!\.)')

    bracket_to_dot_regex = re.compile(
        rf'({VNR}[\w$]*)\s*\[\s*(["\'])({VNR}[\w$]*)\2\s*\]'
    )

    # --- 2. Helper Functions ---

    def parse_js_number(num_str):
        num_str = num_str.strip()
        try:
            if num_str.lower().startswith('0x'): return int(num_str, 16)
            elif num_str.lower().startswith('0o'): return int(num_str, 8)
            elif num_str.startswith('0') and len(num_str) > 1 and '.' not in num_str: return int(num_str, 8)
            else: return int(num_str)
        except ValueError: return None

    def eval_math_match(match):
        n1_str, op, n2_str = match.groups()
        n1, n2 = parse_js_number(n1_str), parse_js_number(n2_str)
        if n1 is None or n2 is None: return match.group(0)

        try:
            res = 0
            # Arithmetic
            if op == '+': res = n1 + n2
            elif op == '-': res = n1 - n2
            elif op == '*': res = n1 * n2
            elif op == '/': res = n1 / n2
            elif op == '%': res = n1 % n2
            # Bitwise (emulate JS 32-bit integers)
            elif op == '&': res = n1 & n2
            elif op == '|': res = n1 | n2
            elif op == '^': res = n1 ^ n2
            elif op == '<<': res = (n1 << n2) & 0xFFFFFFFF
            elif op == '>>': 
                n1_32 = n1 if n1 < 0x80000000 else n1 - 0x100000000
                res = (n1_32 >> n2) & 0xFFFFFFFF
            elif op == '>>>': res = (n1 >> n2) & 0xFFFFFFFF

            if isinstance(res, float) and res.is_integer(): res = int(res)
            return str(res)
        except: return match.group(0)

    # --- 3. Main Loop ---

    prev_code = None
    
    # Loop until the code stops changing
    while prev_code != js_code:
        prev_code = js_code
        
        # Pass 1: Solve Math
        js_code = math_regex.sub(eval_math_match, js_code)
        
        # Pass 2: Remove redundant parentheses around numbers
        js_code = paren_regex.sub(r'\1', js_code)

        # Pass 3: Convert identifier['prop'] to identifier.prop
        # Replacement: Object.Prop
        js_code = bracket_to_dot_regex.sub(r'\1.\3', js_code)

    return js_code

def getFile(file):
    with open(file) as f:
        return f.read()

def executeJS(file):
    return subprocess.run(['node', file + '.js'], capture_output=True, text=True)

def deobfuscate(file):
    try:
        aware = input("""
[!] This deobfuscator performs dynamic analysis, which can involve running untrusted code.
[!] Do not proceed if you are not in a VM or sandbox or you do not trust the code.
[!] Do you know what you are doing? (yes/no, in full) """)
        if aware != "yes":
            return
    except KeyboardInterrupt:
        return

    code = getFile(file)
    property = re.compile('let (.*?);').findall(code)[0]
    print("[*] Attempting to perform dynamic analysis for extracting second layer of obfuscated code...")
    result = executeJS('jsdefender-deobfuscate')
    
    if result.stderr:
        print("[!] Error when performing step 1 of dynamic analysis, cannot proceed.")
        print(result.stderr)
        return

    layer2 = result.stdout

    found_instances = re.compile(rf"function ({VNR}+)\({VNR}+\){{return ({VNR}+)\[", flags=re.VERBOSE).findall(layer2)
    found_instances = [i[1] for i in found_instances]
    found_instances_reduced = list(set(found_instances))
    try:
        extracted_string_var = found_instances_reduced[0]
    except:
        print("[!] No found instances, cannot extract string variable and thus cannot proceed.")
        return

    print("[*] Successfully extracted second layer.")

    stringVarSetter = f""";
globalThis['functions']=[];
globalThis['stringArray']={extracted_string_var};
for (const i in {property}) functions.push(i);
}})()"""
    stringVarGetter = ";console.log(JSON.stringify([stringArray,functions]))"
    updated_decrypted = layer2[:-3] + stringVarSetter + stringVarGetter
    with open("temp_jsdefender_strarr.js", "w") as f:
        f.write(updated_decrypted)

    print("[*] Injected setters and getters to sneak in on variables.")
    print("[*] Attempting to perform step 2 of dynamic analysis...")

    result = executeJS('temp_jsdefender_strarr')
    
    if result.stderr:
        print("[!] Error when performing step 2 of dynamic analysis, cannot proceed.")
        print(result.stderr)
        return

    stringArrayText = result.stdout.replace("'", '"')
    stringArray = json.loads(stringArrayText)

    strings = stringArray[0]
    functions = stringArray[1]

    print("[*] Successfully extracted strings and variables!")
    print("[*] Extracting the actual code...")

    actual_code = ")}();".join(code.split(")}();")[1:])

    obfuscated_indexers = []
    property_indirection_disabled = False
    for function in functions:
        # With property indirection enabled
        found_indexers = re.compile(fr"{property}\.{function}\(\d+\)").findall(actual_code)
        obfuscated_indexers.extend(found_indexers)

        # With property indirection disabled
        found_indexers_2 = re.compile(fr"{property}\.{function}\(\)").findall(actual_code)
        if len(found_indexers_2) >= len(found_indexers) and not property_indirection_disabled:
            print("[!] Property indirection appears to have been disabled for this file.")
            property_indirection_disabled = True
        obfuscated_indexers.extend(found_indexers_2)

    used_strings = []
    for indexer in obfuscated_indexers:
        index = indexer.split("(")[1].split(")")[0]
        if index:
            index = int(index)
            string = strings[index]
            used_strings.append(string)
            actual_code = actual_code.replace(indexer, repr(string))

    for string in used_strings:
        return_value = re.compile(fr"{property}\.{string}=function\(\){{return (.*?)}}").findall(updated_decrypted)
        if len(return_value) > 0:
            return_value = return_value[0]
            return_value_deobfuscated = str(simple_eval(return_value))
            actual_code = re.sub(fr"{property}\['{string}'\]\(\)", return_value_deobfuscated, actual_code)

    should_iterate = property_indirection_disabled
    if len(sys.argv) >= 2:
        should_iterate = \
            should_iterate \
            or sys.argv[1] == "PROPERTY_INDIRECTION_DISABLED"
    
    if should_iterate:
        for function in functions:
            return_value = re.compile(fr"{property}\.{function}=function\(\){{return (.*?)}}").findall(updated_decrypted)
            if len(return_value) > 0:
                return_value = return_value[0]
                return_value_deobfuscated = str(simple_eval(return_value))
                actual_code = re.sub(fr"{property}.{function}\(\)", return_value_deobfuscated, actual_code)

    print("[*] Nearly there, we just need to simplify and...\n")

    print(simplify(actual_code))
    unflatten(actual_code)

deobfuscate("jsdefender.js")