import { useEffect, useRef, useState } from "react";
import {
  AmbientLight,
  BufferAttribute,
  BufferGeometry,
  Color,
  DoubleSide,
  EdgesGeometry,
  ExtrudeGeometry,
  Group,
  Line,
  LineBasicMaterial,
  LineLoop,
  LineSegments,
  Mesh,
  MeshBasicMaterial,
  MeshPhysicalMaterial,
  PerspectiveCamera,
  Points,
  PointsMaterial,
  PointLight,
  RingGeometry,
  Scene,
  Shape,
  SphereGeometry,
  SRGBColorSpace,
  TorusGeometry,
  Vector3,
  WebGLRenderer,
} from "three";

type ShieldMode = "secure" | "elevated" | "high-risk" | "blocked" | "approval" | "sandbox";
type Props = {
  mode: ShieldMode;
  pulseKey: number;
  reducedMotion: boolean;
  onActivate: () => void;
};

const MODE_COLORS: Record<ShieldMode, { edge: number; glow: number }> = {
  secure: { edge: 0x7beeff, glow: 0x168fd1 },
  elevated: { edge: 0xffc978, glow: 0xd88735 },
  "high-risk": { edge: 0xff6a80, glow: 0xc92148 },
  blocked: { edge: 0xff6078, glow: 0xd51f45 },
  approval: { edge: 0xffd17d, glow: 0xd89336 },
  sandbox: { edge: 0xc1a1ff, glow: 0x7955d9 },
};

function shieldShape() {
  const shape = new Shape();
  shape.moveTo(0, 1.38);
  shape.lineTo(0.98, 1.02);
  shape.lineTo(0.85, 0.16);
  shape.quadraticCurveTo(0.72, -0.62, 0, -1.2);
  shape.quadraticCurveTo(-0.72, -0.62, -0.85, 0.16);
  shape.lineTo(-0.98, 1.02);
  shape.closePath();
  return shape;
}

type SceneControls = (mode: ShieldMode, pulseKey: number) => void;

export default function ShieldScene({
  mode,
  pulseKey,
  reducedMotion,
  onActivate,
}: Props) {
  const hostRef = useRef<HTMLDivElement>(null);
  const controlsRef = useRef<SceneControls | null>(null);
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    let renderer: WebGLRenderer;
    try {
      renderer = new WebGLRenderer({
        alpha: true,
        antialias: true,
        powerPreference: "low-power",
      });
    } catch {
      setUnavailable(true);
      return;
    }

    setUnavailable(false);
    const scene = new Scene();
    const camera = new PerspectiveCamera(36, 1, 0.1, 50);
    camera.position.set(0, 0, 5.2);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
    renderer.outputColorSpace = SRGBColorSpace;
    renderer.setClearColor(0x000000, 0);
    host.appendChild(renderer.domElement);

    const root = new Group();
    scene.add(root);
    scene.add(new AmbientLight(0x8dbbd7, 1.65));

    const edgeLight = new PointLight(0x7beeff, 42, 12);
    edgeLight.position.set(-2.2, 1.6, 3.2);
    scene.add(edgeLight);
    const coreLight = new PointLight(0x168fd1, 34, 10);
    coreLight.position.set(0, 0, 1.35);
    scene.add(coreLight);
    const violetLight = new PointLight(0x7867ff, 14, 9);
    violetLight.position.set(2.4, -1.4, -1);
    scene.add(violetLight);

    const colors = MODE_COLORS[mode];
    const shape = shieldShape();
    const layers: MeshPhysicalMaterial[] = [];
    const edgeMaterials: LineBasicMaterial[] = [];
    const layerSpecs = [
      { scale: 1.04, z: -0.1, depth: 0.12, opacity: 0.22, tint: 0x153b55 },
      { scale: 0.92, z: 0.08, depth: 0.14, opacity: 0.61, tint: 0x174765 },
      { scale: 0.79, z: 0.22, depth: 0.1, opacity: 0.25, tint: 0x235975 },
    ];

    for (const [index, layer] of layerSpecs.entries()) {
      const geometry = new ExtrudeGeometry(shape, {
        depth: layer.depth,
        bevelEnabled: true,
        bevelSegments: 4,
        steps: 1,
        bevelSize: index === 0 ? 0.065 : 0.045,
        bevelThickness: 0.045,
        curveSegments: 12,
      });
      const material = new MeshPhysicalMaterial({
        color: layer.tint,
        metalness: 0.72,
        roughness: 0.17,
        clearcoat: 1,
        clearcoatRoughness: 0.12,
        transparent: true,
        opacity: layer.opacity,
        side: DoubleSide,
        emissive: colors.glow,
        emissiveIntensity: index === 1 ? 0.34 : 0.2,
      });
      const mesh = new Mesh(geometry, material);
      mesh.scale.setScalar(layer.scale);
      mesh.position.z = layer.z;
      root.add(mesh);
      layers.push(material);

      const edgeMaterial = new LineBasicMaterial({
        color: colors.edge,
        transparent: true,
        opacity: index === 0 ? 0.94 : 0.48,
      });
      root.add(new LineSegments(new EdgesGeometry(geometry, 18), edgeMaterial));
      edgeMaterials.push(edgeMaterial);
    }

    const crestGeometry = new BufferGeometry().setFromPoints([
      new Vector3(-0.4, 0.08, 0.46),
      new Vector3(-0.1, -0.23, 0.46),
      new Vector3(0.43, 0.38, 0.46),
    ]);
    const crestMaterial = new LineBasicMaterial({
      color: colors.edge,
      transparent: true,
      opacity: 0.82,
    });
    root.add(new Line(crestGeometry, crestMaterial));
    edgeMaterials.push(crestMaterial);

    const coreShellMaterial = new MeshPhysicalMaterial({
      color: 0x3e9dbd,
      metalness: 0.55,
      roughness: 0.13,
      clearcoat: 1,
      transparent: true,
      opacity: 0.42,
      emissive: colors.glow,
      emissiveIntensity: 0.7,
    });
    const coreShell = new Mesh(new SphereGeometry(0.43, 32, 24), coreShellMaterial);
    coreShell.position.set(0, 0.08, 0.62);
    root.add(coreShell);
    const coreMaterial = new MeshBasicMaterial({
      color: 0xbaf8ff,
      transparent: true,
      opacity: 0.9,
    });
    const core = new Mesh(new SphereGeometry(0.16, 24, 18), coreMaterial);
    core.position.copy(coreShell.position);
    root.add(core);

    const orbitMaterials: MeshBasicMaterial[] = [];
    const targetEdgeColor = new Color(colors.edge);
    const targetGlowColor = new Color(colors.glow);
    const orbitalSpecs = [
      { radius: 0.53, tube: 0.012, x: 0.28, y: 0.78, z: 0.15, speed: 0.72 },
      { radius: 0.66, tube: 0.008, x: 1.04, y: 0.35, z: -0.28, speed: -0.42 },
      { radius: 0.76, tube: 0.006, x: 0.58, y: 1.16, z: 0.4, speed: 0.25 },
    ];
    const orbitals = orbitalSpecs.map((spec, index) => {
      const material = new MeshBasicMaterial({
        color: index === 1 ? 0x9d8aff : colors.edge,
        transparent: true,
        opacity: 0.66 - index * 0.1,
      });
      orbitMaterials.push(material);
      const mesh = new Mesh(
        new TorusGeometry(spec.radius, spec.tube, 8, 96),
        material,
      );
      mesh.rotation.set(spec.x, spec.y, spec.z);
      root.add(mesh);
      return { mesh, speed: spec.speed };
    });

    const shieldHaloMaterial = new MeshBasicMaterial({
      color: colors.glow,
      transparent: true,
      opacity: 0.16,
      side: DoubleSide,
    });
    const shieldHalo = new Mesh(
      new RingGeometry(1.31, 1.37, 96),
      shieldHaloMaterial,
    );
    shieldHalo.position.z = -0.42;
    root.add(shieldHalo);
    const systemOrbitMaterial = new MeshBasicMaterial({
      color: colors.edge,
      transparent: true,
      opacity: 0.23,
    });
    const systemOrbit = new Mesh(
      new TorusGeometry(1.72, 0.007, 6, 128),
      systemOrbitMaterial,
    );
    systemOrbit.rotation.set(0.25, 0.58, 0);
    root.add(systemOrbit);
    orbitMaterials.push(systemOrbitMaterial, shieldHaloMaterial);
    const defensivePulseMaterial = new MeshBasicMaterial({
      color: colors.edge,
      transparent: true,
      opacity: 0,
      side: DoubleSide,
      depthWrite: false,
    });
    const defensivePulse = new Mesh(
      new RingGeometry(0.62, 0.66, 96),
      defensivePulseMaterial,
    );
    defensivePulse.position.z = 0.8;
    root.add(defensivePulse);
    orbitMaterials.push(defensivePulseMaterial);

    const circuitMaterial = new LineBasicMaterial({
      color: colors.edge,
      transparent: true,
      opacity: 0.42,
    });
    const circuits = [
      [[-0.7, 0.68, 0.29], [-0.46, 0.51, 0.34], [-0.32, 0.51, 0.34]],
      [[0.7, 0.68, 0.29], [0.46, 0.51, 0.34], [0.32, 0.51, 0.34]],
      [[-0.56, -0.28, 0.3], [-0.39, -0.1, 0.34], [-0.3, -0.1, 0.34]],
      [[0.56, -0.28, 0.3], [0.39, -0.1, 0.34], [0.3, -0.1, 0.34]],
    ];
    circuits.forEach((points) => {
      const geometry = new BufferGeometry().setFromPoints(
        points.map(([x, y, z]) => new Vector3(x, y, z)),
      );
      root.add(new Line(geometry, circuitMaterial));
    });

    const nodeMaterial = new MeshBasicMaterial({
      color: colors.edge,
      transparent: true,
      opacity: 0.86,
    });
    const nodePositions = [
      new Vector3(-1.43, 0.18, 0.12),
      new Vector3(-1.14, 0.86, -0.1),
      new Vector3(1.43, 0.18, 0.12),
      new Vector3(1.14, -0.67, -0.12),
      new Vector3(0, 1.66, -0.15),
      new Vector3(0, -1.62, -0.15),
    ];
    const nodeMeshes = nodePositions.map((position, index) => {
      const node = new Mesh(
        new SphereGeometry(index < 2 ? 0.035 : 0.045, 12, 10),
        nodeMaterial,
      );
      node.position.copy(position);
      root.add(node);
      return node;
    });
    const topologyMaterial = new LineBasicMaterial({
      color: colors.edge,
      transparent: true,
      opacity: 0.23,
    });
    const topologyPairs = [[0, 1], [1, 4], [4, 2], [2, 3], [3, 5], [5, 0]];
    topologyPairs.forEach(([from, to]) => {
      const geometry = new BufferGeometry().setFromPoints([
        nodePositions[from],
        nodePositions[to],
      ]);
      root.add(new Line(geometry, topologyMaterial));
    });

    const particleCount = 150;
    const particlePositions = new Float32Array(particleCount * 3);
    for (let index = 0; index < particleCount; index += 1) {
      const offset = index * 3;
      const seed = index * 12.9898;
      particlePositions[offset] = Math.sin(seed) * 2.45;
      particlePositions[offset + 1] = Math.cos(seed * 1.73) * 1.8;
      particlePositions[offset + 2] = Math.sin(seed * 0.57) * 1.35 - 0.8;
    }
    const particleGeometry = new BufferGeometry();
    particleGeometry.setAttribute(
      "position",
      new BufferAttribute(particlePositions, 3),
    );
    const particleMaterial = new PointsMaterial({
      color: colors.edge,
      size: 0.017,
      transparent: true,
      opacity: 0.54,
      sizeAttenuation: true,
    });
    const particles = new Points(particleGeometry, particleMaterial);
    scene.add(particles);

    const pointer = { x: 0, y: 0 };
    const handlePointerMove = (event: PointerEvent) => {
      if (reducedMotion) return;
      const bounds = host.getBoundingClientRect();
      pointer.x = ((event.clientX - bounds.left) / bounds.width - 0.5) * 0.3;
      pointer.y = ((event.clientY - bounds.top) / bounds.height - 0.5) * 0.2;
    };
    host.addEventListener("pointermove", handlePointerMove, { passive: true });

    const resize = () => {
      const width = Math.max(host.clientWidth, 1);
      const height = Math.max(host.clientHeight, 1);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height, false);
      renderer.render(scene, camera);
    };
    const resizeObserver = typeof ResizeObserver === "undefined"
      ? null
      : new ResizeObserver(resize);
    if (resizeObserver) resizeObserver.observe(host);
    else {
      window.addEventListener("resize", resize);
      resize();
    }

    let activeMode = mode;
    let activePulse = pulseKey;
    let pulseStartedAt = 0;
    const setSceneMode = (nextMode: ShieldMode, nextPulse: number) => {
      if (nextMode !== activeMode) {
        activeMode = nextMode;
        const nextColors = MODE_COLORS[nextMode];
        targetEdgeColor.setHex(nextColors.edge);
        targetGlowColor.setHex(nextColors.glow);
        layers.forEach((material, index) => {
          material.emissiveIntensity = nextMode === "blocked" ? 0.72 : nextMode === "high-risk" ? 0.58 : index === 1 ? 0.34 : 0.2;
        });
        violetLight.intensity = nextMode === "approval" ? 30 : 14;
      }
      if (nextPulse !== activePulse) {
        activePulse = nextPulse;
        if (!reducedMotion) pulseStartedAt = performance.now();
      }
      if (reducedMotion) {
        layers.forEach((material) => material.emissive.copy(targetGlowColor));
        edgeMaterials.forEach((material) => material.color.copy(targetEdgeColor));
        orbitMaterials.forEach((material) => material.color.copy(targetEdgeColor));
        nodeMaterial.color.copy(targetEdgeColor);
        topologyMaterial.color.copy(targetEdgeColor);
        circuitMaterial.color.copy(targetEdgeColor);
        particleMaterial.color.copy(targetEdgeColor);
        coreShellMaterial.emissive.copy(targetGlowColor);
        coreMaterial.color.copy(targetEdgeColor);
        edgeLight.color.copy(targetEdgeColor);
        coreLight.color.copy(targetGlowColor);
        renderer.render(scene, camera);
      }
    };
    controlsRef.current = setSceneMode;

    let frame = 0;
    const startedAt = performance.now();
    const renderFrame = () => {
      const elapsed = (performance.now() - startedAt) / 1000;
      const pulse = pulseStartedAt && !reducedMotion
        ? Math.max(0, 1 - (performance.now() - pulseStartedAt) / 850)
        : 0;
      if (!reducedMotion) {
        layers.forEach((material) => material.emissive.lerp(targetGlowColor, 0.055));
        edgeMaterials.forEach((material) => material.color.lerp(targetEdgeColor, 0.055));
        orbitMaterials.forEach((material) => material.color.lerp(targetEdgeColor, 0.055));
        nodeMaterial.color.lerp(targetEdgeColor, 0.055);
        topologyMaterial.color.lerp(targetEdgeColor, 0.055);
        circuitMaterial.color.lerp(targetEdgeColor, 0.055);
        particleMaterial.color.lerp(targetEdgeColor, 0.055);
        coreShellMaterial.emissive.lerp(targetGlowColor, 0.055);
        coreMaterial.color.lerp(targetEdgeColor, 0.055);
        edgeLight.color.lerp(targetEdgeColor, 0.055);
        coreLight.color.lerp(targetGlowColor, 0.055);
      }
      if (!reducedMotion) {
        const motionScale = activeMode === "approval" ? 0.35 : activeMode === "sandbox" ? 0.6 : 1;
        const modeAcceleration = activeMode === "high-risk" || activeMode === "blocked" ? 1.35 : 1;
        const rotationBoost = (1 + pulse * 1.9) * motionScale * modeAcceleration;
        const corePulseSpeed = activeMode === "high-risk" || activeMode === "blocked"
          ? 4.2
          : activeMode === "elevated"
            ? 3.2
            : activeMode === "approval" || activeMode === "sandbox"
              ? 0.8
              : 2.2;
        root.rotation.y += (pointer.x - root.rotation.y) * 0.026 + 0.003 * rotationBoost;
        root.rotation.x += (pointer.y + Math.sin(elapsed * 0.42 * motionScale) * 0.035 - root.rotation.x) * 0.035;
        root.position.y = Math.sin(elapsed * 0.7 * motionScale) * 0.045 * motionScale;
        orbitals.forEach(({ mesh, speed }) => {
          mesh.rotation.z += speed * 0.003 * rotationBoost;
        });
        systemOrbit.rotation.z = elapsed * 0.08 * motionScale;
        core.scale.setScalar(1 + Math.sin(elapsed * corePulseSpeed) * 0.055 + pulse * 0.4);
        coreShell.scale.setScalar(1 + Math.sin(elapsed * 1.35 * motionScale) * 0.035 + pulse * 0.14);
        nodeMeshes.forEach((node, index) => {
          node.scale.setScalar(1 + Math.sin(elapsed * 1.7 + index) * 0.2);
        });
        particles.rotation.y = elapsed * 0.018 * motionScale;
        particles.position.y = Math.sin(elapsed * 0.4) * 0.035;
        shieldHalo.scale.setScalar(1 + Math.sin(elapsed * 1.25) * 0.025 + pulse * 0.24);
        shieldHaloMaterial.opacity = 0.14 + pulse * 0.25;
        coreLight.intensity = 30 + Math.sin(elapsed * corePulseSpeed) * 5 + pulse * 50;
        const pulseProgress = 1 - pulse;
        defensivePulse.scale.setScalar(0.72 + pulseProgress * 1.45);
        defensivePulseMaterial.opacity = pulse * (activeMode === "blocked" ? 0.85 : 0.42);
      }
      renderer.render(scene, camera);
      if (!reducedMotion) frame = requestAnimationFrame(renderFrame);
    };
    renderFrame();

    return () => {
      cancelAnimationFrame(frame);
      if (controlsRef.current === setSceneMode) controlsRef.current = null;
      resizeObserver?.disconnect();
      if (!resizeObserver) window.removeEventListener("resize", resize);
      host.removeEventListener("pointermove", handlePointerMove);
      scene.traverse((object) => {
        if (
          object instanceof Mesh ||
          object instanceof Line ||
          object instanceof LineLoop ||
          object instanceof LineSegments ||
          object instanceof Points
        ) {
          object.geometry.dispose();
          const materials = Array.isArray(object.material)
            ? object.material
            : [object.material];
          materials.forEach((material) => material.dispose());
        }
      });
      renderer.dispose();
      renderer.domElement.remove();
    };
  }, [reducedMotion]);

  useEffect(() => {
    controlsRef.current?.(mode, pulseKey);
  }, [mode, pulseKey]);

  return (
    <div
      className={`shield-canvas ${unavailable ? "shield-canvas-unavailable" : ""}`}
      ref={hostRef}
      role="button"
      aria-label={`Activate the interactive AgentShield ${mode} security emblem`}
      tabIndex={0}
      onClick={onActivate}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onActivate();
        }
      }}
    />
  );
}
