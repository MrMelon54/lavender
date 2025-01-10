<script lang="ts">
  import {onMount} from "svelte";

  let textCopyElement: HTMLSpanElement;

  export let text: string;

  onMount(() => {
    selectText(textCopyElement);
  });

  // Thanks again: https://stackoverflow.com/a/987376
  function selectText(node: HTMLElement) {

    if ((document.body as any).createTextRange) {
      const range = (document.body as any).createTextRange();
      range.moveToElementText(node);
      range.select();
    } else if (window.getSelection) {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(node as any);
      (selection as any).removeAllRanges();
      (selection as any).addRange(range);
    } else {
      console.warn("Could not select text in node: Unsupported browser.");
    }
  }
</script>

<span bind:this={textCopyElement}>{text}</span>
