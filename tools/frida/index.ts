import assert from "assert"
import { writeFileSync } from "fs"
const target_address = Memory.scanSync(Process.mainModule.base, Process.mainModule.size, "48 8B 05 ?? ?? ?? ?? 48 8B 00 48 85 C0 74 0A")[0].address;
interface BacktraceNode {
  children: { [key: string]: BacktraceNode };
  count: number;
}

class BacktraceAggregator {
  private root: BacktraceNode;

  constructor() {
    this.root = { children: {}, count: 0 };
  }

  addBacktrace(trace: string[]): void {
    let current: BacktraceNode = this.root;
    for (let func of trace) {
      if (!current.children[func]) {
        current.children[func] = { children: {}, count: 0 };
      }
      current = current.children[func];
      current.count++;
    }
  }

  getCount(trace: string[]): number {
    let current: BacktraceNode = this.root;
    for (let func of trace) {
      if (!current.children[func]) {
        return 0;
      }
      current = current.children[func];
    }
    return current.count;
  }
  printTree(): void {
    const dfs = (node: BacktraceNode, prefix: string = '', isLast: boolean = true): void => {
      // 跳过根节点，直接从其子节点开始
      const keys = Object.keys(node.children);
      keys.forEach((key, index) => {
        const child = node.children[key];
        const branch = (index === keys.length - 1) ? '└── ' : '├── ';
        const newPrefix = prefix + (isLast ? '    ' : '│   ');
        console.log(prefix + (keys.length > 0 ? branch : '') + key + ` (count: ${child.count})`);
        dfs(child, newPrefix, index === keys.length - 1);
      });
    };
    console.log('root');
    dfs(this.root, '', true);
  }
}

const backtraceAggregator = new BacktraceAggregator();

function EntityReadLocalPosition(ptr: NativePointer) {
    const x = ptr.readFloat();

}
const localposition = { base: new NativePointer(target_address), size: 0x4 }
MemoryAccessMonitor.enable(localposition, {
    onAccess(details) {
        EntityReadLocalPosition((details.context as X64CpuContext).rbx.add(0x44))
        backtraceAggregator.addBacktrace(Thread.backtrace(details.context, Backtracer.ACCURATE).map(Object.toString));
    },
})
