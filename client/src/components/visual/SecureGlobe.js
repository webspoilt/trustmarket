import React, { useRef } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Sphere, MeshDistortMaterial, Stars } from '@react-three/drei';

const AnimatedSphere = () => {
    const meshRef = useRef();

    useFrame(({ clock }) => {
        if (meshRef.current) {
            meshRef.current.rotation.x = clock.getElapsedTime() * 0.1;
            meshRef.current.rotation.y = clock.getElapsedTime() * 0.15;
        }
    });

    return (
        <Sphere ref={meshRef} args={[1, 100, 200]} scale={2.5}>
            <MeshDistortMaterial
                color="#6366f1"
                attach="material"
                distort={0.4}
                speed={1.5}
                roughness={0.1}
                metalness={0.8}
            />
        </Sphere>
    );
};

const SecureGlobe = () => {
    return (
        <div className="absolute inset-0 z-0 pointer-events-none opacity-60">
            <Canvas camera={{ position: [0, 0, 5], fov: 45 }}>
                <ambientLight intensity={0.5} />
                <directionalLight position={[10, 10, 5]} intensity={1} />
                <pointLight position={[-10, -10, -5]} intensity={0.5} color="purple" />
                <AnimatedSphere />
                <Stars radius={100} depth={50} count={5000} factor={4} saturation={0} fade speed={1} />
            </Canvas>
        </div>
    );
};

export default SecureGlobe;
