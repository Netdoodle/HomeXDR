import re,sys,os
src=open(sys.argv[1]).read(); outdir=sys.argv[2]
P=[re.search(r' d="([^"]*)"',p).group(1) for p in re.findall(r'<path [^>]*?/>',src)]
NAVY,CYAN='#0c1e3f','#69d8f4'
def subs(d): return [s for s in re.split(r'(?=[Mm])',d) if s]
tile=''.join(subs(P[0])[:3])            # tile minus shield silhouette & bottom arc (knob hole dropped: it is redrawn by the motif)
sil=subs(P[1])[0]                        # cyan shield + circuit silhouette
# motif zone = the original navy well (P3) with the house-hugging stretch replaced by a straight floor
d3=P[2]
toks=re.findall(r'[A-Za-z]|-?(?:\d+\.?\d*|\.\d+)(?:e-?\d+)?',d3)
# tokens 8..13 = curve ending at 393.78,661.35 ; tokens 176..181 = curve ending at 630.2,661.34
assert toks[182]=='a', toks[180:184]
zone=' '.join(toks[:14])+' L393.78 684 L630.2 684 L630.2 661.34 '+' '.join(toks[182:])
zone=re.sub(r' (?=[A-Za-z])|(?<=[A-Za-z]) ','',zone)
def path(fill,d,extra=''): return f'<path fill="{fill}"{extra} d="{d}"/>'
EO=' fill-rule="evenodd"'
core=[ '<g id="base">',
 path(NAVY,P[0],EO), path(CYAN,P[1],EO), path(NAVY,P[5]), path(CYAN,P[6]), path(NAVY,P[7]), path(NAVY,P[9]), '</g>']
empty=['<use id="motif-zone-fill" href="#motif-zone" fill="'+NAVY+'"/>']
defs=f'<defs><path id="motif-zone" d="{zone}"/><clipPath id="motif-clip"><use href="#motif-zone"/></clipPath></defs>'
motif=['<g id="motif-home">',
 f'<path fill="{CYAN}" clip-path="url(#motif-clip)" d="{sil}"/>',
 path(NAVY,P[2]), path(NAVY,P[3]), path(CYAN,P[4]), path(CYAN,P[8]), path(CYAN,P[10]), '</g>']
head='<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">'
def w(name,body): open(os.path.join(outdir,name),'w').write(head+'\n'+'\n'.join(body)+'\n</svg>\n')
cuts=['<g id="motif-home">']+motif[2:]
w('base.svg',[defs]+core+empty)
w('shield-home.svg',core+['<!-- swappable motif (house): navy cuts + cyan parts inside the motif zone -->']+cuts)
w('motif-home.svg',[defs]+motif)
