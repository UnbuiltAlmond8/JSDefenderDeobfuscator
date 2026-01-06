import json
import re
import subprocess

try:
    import requests
    from getpass import getpass
    from simpleeval import simple_eval
except ImportError:
    print("[!] Missing dependencies.")
    print("[!] Required: requests, getpass, simpleeval")
    exit()

import re
import base64

def encode_tifinagh_sequences(text):
    # 1. Define the Regex for the Tifinagh Unicode block (U+2D30 to U+2D7F)
    # The '+' ensures we grab the whole sequence (word) at once.
    tifinagh_pattern = r'[\u2D30-\u2D7F]+'

    # 2. Define the replacement callback function
    def replacer(match):
        # Get the matched string
        symbol_sequence = match.group(0)
        
        # Convert to bytes (UTF-8)
        data_bytes = symbol_sequence.encode('utf-8')
        
        # Encode to URL-safe Base64
        # (This uses '-' and '_' instead of '+' and '/')
        encoded_bytes = base64.urlsafe_b64encode(data_bytes)
        
        # Decode back to string to insert into the result
        final = "a" + encoded_bytes.decode('utf-8')
        for i in range(0, 9):
            final = final.replace(str(i), "ABCDEFGHIJ"[i])

        return final.replace('-', '$')

    # 3. Use re.sub to find and replace
    result = re.sub(tifinagh_pattern, replacer, text)
    if text != result:
        print("[!] Warning: Tifinagh variable names detected. Variable names needed to be longer.")
    return result

def unflatten(js_code):
    OFFER = input("\n[*] Want to rename variables and unflatten the control flow? (yes/no) ")
    if OFFER.startswith("y"):
        comments = input("[*] Add comments? (yes/no) ").startswith("y")
    else:
        print("[!] Cntrol flow may not have been unflattened.")
        print("[!] Variables have not been renamed.")
        return

    API_KEY = getpass("Google Gemini API Key: ")
    if not API_KEY:
        print('[!] Error unflattening, API key was not provided.')
        return
    
    USER_INPUT = f"""
Rename the variables, simplify expressions, and unflatten the control flow of this JavaScript script.
Wrap the resulting code in a javascript code block.

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
    """
    1. Simplifies arithmetic (0x1 + 0x2 -> 3).
    2. Removes redundant parentheses ((10) -> 10).
    3. Converts bracket notation to dot notation (console['log'] -> console.log).
    """

    # --- 1. Define Regex Patterns ---

    # A. MATH PATTERNS
    # Matches Hex, Octal, Decimal
    num_pattern = r'(?:0[xX][0-9a-fA-F]+|0[oO][0-7]+|0[0-7]*|[1-9]\d*|0)'
    op_pattern = r'(?:>>>|<<|>>|[-+*/%&|^])'
    # Group 1: Left, Group 2: Op, Group 3: Right
    math_regex = re.compile(fr'({num_pattern})\s*({op_pattern})\s*({num_pattern})')

    # B. PARENTHESIS PATTERNS
    # Matches ( Number )
    # Lookbehind (?<![\w$]): Ensure not preceded by word char (prevents function calls)
    # Lookahead (?!\.): Ensure not followed by dot (prevents (5).toString())
    paren_regex = re.compile(fr'(?<![\w$])\(\s*({num_pattern})\s*\)(?!\.)')

    # C. DOT NOTATION PATTERNS
    # Matches: identifier['property'] or identifier["property"]
    # Group 1: Object Name (Must be valid JS identifier)
    # Group 2: Quote type (' or ")
    # Group 3: Property Name (Must be valid JS identifier to switch to dot notation)
    # \2: Backreference ensures closing quote matches opening quote
    bracket_to_dot_regex = re.compile(
        r'([a-zA-Z_$][\w$]*)\s*\[\s*(["\'])([a-zA-Z_$][\w$]*)\2\s*\]'
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

    code = encode_tifinagh_sequences(getFile(file))
    property = re.compile('let (.*?);').findall(code)[0]
    print("[*] Attempting to perform dynamic analysis for extracting second layer of obfuscated code...")
    result = executeJS('jsdefender-deobfuscate')
    
    if result.stderr:
        print("[!] Error when performing step 1 of dynamic analysis, cannot proceed.")
        print(result.stderr)
        return

    layer2 = encode_tifinagh_sequences(result.stdout)

    found_instances = re.compile(r"function ([a-zA-Z]+)\([a-zA-Z]+\){return ([a-zA-Z]+)\[").findall(layer2)
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
    for function in functions:
        found_indexers = re.compile(fr"{property}\.{function}\(\d+\)").findall(actual_code)
        obfuscated_indexers.extend(found_indexers)

    used_strings = []
    for indexer in obfuscated_indexers:
        index = int(indexer.split("(")[1].split(")")[0])
        string = strings[index]
        used_strings.append(string)
        actual_code = actual_code.replace(indexer, repr(string))

    for string in used_strings:
        return_value = re.compile(f"{property}\\.{string}=function\\(\\){{return (.*?)}}").findall(updated_decrypted)
        if len(return_value) > 0:
            return_value = return_value[0]
            return_value_deobfuscated = str(simple_eval(return_value)) # or ast.literal_eval
            actual_code = re.sub(fr"{property}\['{string}'\]\(\)", return_value_deobfuscated, actual_code)
    
    print("[*] Nearly there, we just need to simplify it and...\n")
    final_code = simplify(actual_code)
    print(final_code)
    unflatten(final_code)

deobfuscate("jsdefender.js")