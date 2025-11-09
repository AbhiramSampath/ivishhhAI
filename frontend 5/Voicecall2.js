


import React, { useState, useEffect } from 'react';
import { View, Text, StyleSheet, ImageBackground, TouchableOpacity, Alert } from 'react-native';
import { Svg, Path } from 'react-native-svg';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { connect, disconnect, sendVoiceData, onVoiceTranscript, onVoiceResponse, onCallInitiated, onCallAnswered, onCallEnded, onError } from './api/socket';
import { updateUserLanguage } from './api/index';

// API functions (replaced with socket-based realtime)

// --- Language Component (Provided by you) ---
function Language({ currentLanguage, onLanguageChange }) {
    const [loading, setLoading] = useState(false);

    const handleLanguageToggle = async () => {
        const newLang = currentLanguage === 'ENG' ? 'SPA' : 'ENG';
        setLoading(true);
        try {
            // Mock user data - replace with actual auth context
            const userId = 'user123';
            const deviceFingerprint = 'device123';
            const zkpProof = 'proof123';
            await updateUserLanguage(userId, newLang, deviceFingerprint, zkpProof);
            onLanguageChange(newLang);
        } catch (error) {
            console.error('Error updating language:', error);
            Alert.alert('Error', 'Failed to update language. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <TouchableOpacity onPress={handleLanguageToggle} disabled={loading}>
            <View style={styles.languageContainer}>
                <Text style={[styles.eNG, currentLanguage === 'ENG' && styles.activeLanguage]}>
                    {`ENG`}
                </Text>
                <View style={styles.tablericontransfer}>
                    <Svg style={styles.vector} width="16" height="15" viewBox="0 0 16 15" fill="none">
                        <Path d="M14.6667 5.8335H1.33334L5.91668 0.833496M1.33334 9.16683H14.6667L10.0833 14.1668" stroke="#D1D1D1" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"/>
                    </Svg>
                </View>
                <Text style={[styles.sPA, currentLanguage === 'SPA' && styles.activeLanguage]}>
                    {`SPA`}
                </Text>
                {loading && <Text style={styles.loadingText}>Updating...</Text>}
            </View>
        </TouchableOpacity>
    );
}

// --- Action Buttons ---

function LanguageIcon({ onToggleLanguageDisplay }) { // Renamed prop for clarity
    const [isActive, setIsActive] = useState(false);
    const handlePress = () => {
        const newState = !isActive;
        setIsActive(newState);
        // Notify parent about the change to toggle Language component visibility
        if (onToggleLanguageDisplay) {
            onToggleLanguageDisplay(newState);
        }
    };

    const defaultPathData = "M2.33304 2.3335H13.3097C13.6393 2.33357 13.9615 2.43135 14.2355 2.61449C14.5095 2.79763 14.7231 3.05791 14.8492 3.3624C14.9753 3.6669 15.0083 4.00196 14.944 4.32522C14.8797 4.64847 14.7211 4.94541 14.488 5.1785L12.333 7.3335M7.33304 7.3335C7.33304 9.8335 8.16637 12.3335 3.99970 15.6668M13.9997 27.3335L20.6664 12.3335L27.3330 27.3335M25.8329 24.0002H15.4995";
    const activeFillPath1 = "M2.33304 2.3335H13.3097C13.6393 2.33357 13.9615 2.43135 14.2355 2.61449C14.5095 2.79763 14.7231 3.05791 14.8492 3.3624C14.9753 3.6669 15.0083 4.00196 14.944 4.32522C14.8797 4.64847 14.7211 4.94541 14.488 5.1785L12.333 7.3335";
    const activeFillPath2 = "M7.33304 7.3335C7.33304 9.8335 8.16637 12.3335 3.99970 15.6668L7.33304 7.3335Z";
    const activeFillPath3 = "M13.9997 27.3335L20.6664 12.3335L27.3330 27.3335";
    const activeFillPath4 = "M25.8329 24.0002H15.4995H25.8329Z";
    const activeStrokePath = "M2.33304 2.3335H13.3097C13.6393 2.33357 13.9615 2.43135 14.2355 2.61449C14.5095 2.79763 14.7231 3.05791 14.8492 3.3624C14.9753 3.6669 15.0083 4.00196 14.944 4.32522C14.8797 4.64847 14.7211 4.94541 14.488 5.1785L12.333 7.3335M7.33304 7.3335C7.33304 9.8335 8.16637 12.3335 3.99970 15.6668M13.9997 27.3335L20.6664 12.3335L27.3330 27.3335M25.8329 24.0002H15.4995";

    return (
        <TouchableOpacity onPress={handlePress} style={[styles.iconCircle, isActive && { backgroundColor: "rgba(246, 246, 248, 1)" }]}>
            <View style={styles.iconFrame}>
                <Svg style={styles.languageIconSvg} width="29" height="29" viewBox="0 0 29 29" fill="none" >
                    {isActive ? (
                        <>
                            <Path d={activeFillPath1} fill="#F6F6F8"/>
                            <Path d={activeFillPath2} fill="#F6F6F8"/>
                            <Path d={activeFillPath3} fill="#F6F6F8"/>
                            <Path d={activeFillPath4} fill="#F6F6F8"/>
                            <Path d={activeStrokePath} stroke="#0C0D11" strokeWidth="3.33333" strokeLinecap="round" strokeLinejoin="round"/>
                        </>
                    ) : (
                        <Path d={defaultPathData} stroke="#F6F6F8" strokeWidth="3.33333" strokeLinecap="round" strokeLinejoin="round"/>
                    )}
                </Svg>
            </View>
        </TouchableOpacity>
    );
}

function DialpadIcon() {
    const [isActive, setIsActive] = useState(false);
    const handlePress = () => setIsActive(!isActive);

    return (
        <TouchableOpacity onPress={handlePress} style={[styles.iconCircle, isActive && { backgroundColor: "rgba(246, 246, 248, 1)" }]}>
            <View style={styles.iconFrame}>
                <Svg width="28" height="30" viewBox="0 0 28 30" fill="none" >
                    <Path d="M10.6663 0H17.333V5H10.6663V0ZM10.6663 8.33333H17.333V13.3333H10.6663V8.33333ZM10.6663 16.6667H17.333V21.6667H10.6663V16.6667ZM20.6663 0H27.333V5H20.6663V0ZM20.6663 8.33333H27.333V13.3333H20.6663V8.33333ZM20.6663 16.6667H27.333V21.6667H20.6663V16.6667ZM0.66629 0H7.33296V5H0.66629V0ZM0.66629 8.33333H7.33296V13.3333H0.66629V8.33333ZM0.66629 16.6667H7.33296V21.6667H0.66629V16.6667ZM10.6663 25H17.333V30H10.6663V25Z" fill={isActive ? "#0C0D11" : "#F6F6F8"}/>
                </Svg>
            </View>
        </TouchableOpacity>
    );
}

function SpeakerIcon() {
    const [isActive, setIsActive] = useState(false);
    const handlePress = () => setIsActive(!isActive);

    const activePathData = "M29.1059 1.59403L28.3955 0.571513L26.3504 1.99241L27.0609 3.01327C31.4049 9.26955 31.4049 17.3451 27.0609 23.5881L26.3504 24.609L28.3938 26.0315L29.1059 25.009C33.9728 18.0141 33.9728 8.60392 29.1059 1.59403Z M24.6465 6.03485L24.0274 4.95424L21.8678 6.19088L22.4853 7.2715C24.6183 10.998 24.6183 15.6193 22.4869 19.3326L21.8661 20.4115L24.0257 21.6515L24.6465 20.5725C27.2161 16.0957 27.2161 10.525 24.6465 6.03485Z M7.79421 5.93757H0.0024899V6.76754C-0.000829966 11.1232 -0.000829966 15.4789 0.0024899 19.8362V20.6645H7.79421L14.6431 26.6021H17.0716V0H14.6431L7.79421 5.93757Z";
    const inactivePathPart1 = "M29.1059 1.59403L28.3955 0.571513L26.3504 1.99241L27.0609 3.01327C31.4049 9.26955 31.4049 17.3451 27.0609 23.5881L26.3504 24.609L28.3938 26.0315L29.1059 25.009C33.9728 18.0141 33.9728 8.60392 29.1059 1.59403Z";
    const inactivePathPart2 = "M24.6465 6.03485L24.0274 4.95424L21.8678 6.19088L22.4853 7.2715C24.6183 10.998 24.6183 15.6193 22.4869 19.3326L21.8661 20.4115L24.0257 21.6515L24.6465 20.5725C27.2161 16.0957 27.2161 10.525 24.6465 6.03485Z";
    const inactivePathPart3 = "M7.79421 5.93757H0.0024899V6.76754C-0.000829966 11.1232 -0.000829966 15.4789 0.0024899 19.8362V20.6645H7.79421L14.6431 26.6021H17.0716V0H14.6431L7.79421 5.93757Z";

    return (
        <TouchableOpacity
            onPress={handlePress}
            style={[
                styles.iconCircle,
                isActive ? { backgroundColor: "rgba(246, 246, 248, 1)" } : { backgroundColor: "rgba(119, 119, 119, 0.4)" }
            ]}
        >
            <View style={styles.iconFrame}>
                <Svg width="33" height="27" viewBox="0 0 33 27" fill="none" >
                    {isActive ? (
                        <Path fillRule="evenodd" clipRule="evenodd" d={activePathData} fill="#0C0D11"/>
                    ) : (
                        <>
                            <Path d={inactivePathPart1} fill="#F6F6F8"/>
                            <Path d={inactivePathPart2} fill="#F6F6F8"/>
                            <Path d={inactivePathPart3} fill="#F6F6F8"/>
                        </>
                    )}
                </Svg>
            </View>
        </TouchableOpacity>
    );
}

function AddCallIcon() {
    const handlePress = () => {
        console.log("Add Call button pressed!");
    };

    return (
        <TouchableOpacity onPress={handlePress} style={styles.iconCircle}>
            <View style={styles.iconFrame}>
                <Svg width="31" height="33" viewBox="0 0 31 33" fill="none" >
                    <Path d="M30.9712 14.0929H18.1141V0.521484H13.8284V14.0929H0.971222V18.6167H13.8284V32.1882H18.1141V18.6167H30.9712V14.0929Z" fill="#F6F6F8"/>
                </Svg>
            </View>
        </TouchableOpacity>
    );
}

function VideoIcon() {
    const handlePress = () => {
        console.log("Video button pressed!");
    };

    return (
        <TouchableOpacity onPress={handlePress} style={styles.iconCircle}>
            <View style={styles.iconFrame}>
                <Svg width="32" height="24" viewBox="0 0 32 24" fill="none" >
                    <Path d="M25.5998 4.00029C25.5998 2.23549 24.1646 0.800293 22.3998 0.800293H3.19976C1.43496 0.800293 -0.000244141 2.23549 -0.000244141 4.00029V20.0003C-0.000244141 21.7651 1.43496 23.2003 3.19976 23.2003H22.3998C24.1646 23.2003 25.5998 21.7651 25.5998 20.0003V14.6675L31.9998 20.0003V4.00029L25.5998 9.33309V4.00029Z" fill="#F6F6F8"/>
                </Svg>
            </View>
        </TouchableOpacity>
    );
}

function MuteIcon() {
    const [isMuted, setIsMuted] = useState(true);
    const handlePress = () => setIsMuted(!isMuted);

    const inactiveMutedPath1 = "M27.5759 26.5956L22.8209 21.8406C24.3535 19.8888 25.1872 17.4793 25.1886 14.9976H22.3915C22.3902 16.7378 21.8428 18.4337 20.8266 19.8463L18.8001 17.8184C19.3156 16.9675 19.5901 15.9925 19.5945 14.9976V6.60641C19.5945 3.50586 17.0981 0.98291 14.0297 0.98291C13.9318 0.98291 13.8339 0.995497 13.7374 1.01787C12.3015 1.08749 10.9473 1.70645 9.95493 2.74667C8.9626 3.78689 8.40813 5.16878 8.40622 6.60641V7.42594L2.40233 1.42205L0.424805 3.39957L25.5984 28.5731L27.5759 26.5956ZM5.60916 14.9976H2.8121C2.8121 20.6924 7.0916 25.3971 12.6018 26.0893V28.9829H15.3989V26.0893C16.4812 25.9513 17.5373 25.6544 18.533 25.2083L16.3667 23.0433C15.5985 23.2712 14.8016 23.3875 14.0004 23.3888C9.37261 23.3888 5.60916 19.6253 5.60916 14.9976Z";
    const inactiveMutedPath2 = "M0.345291 0.111816C0.375271 1.83785 1.07428 3.48481 2.29496 4.70548C3.51563 5.92616 5.16259 6.62517 6.88862 6.65515L0.345291 0.111816Z";
    const activeUnmutedPath1 = "M27.5759 26.5956L22.8209 21.8406C24.3535 19.8888 25.1872 17.4793 25.1886 14.9976H22.3915C22.3902 16.7378 21.8428 18.4337 20.8266 19.8463L18.8001 17.8184C19.3156 16.9675 19.5901 15.9925 19.5945 14.9976V6.60641C19.5945 3.50586 17.0981 0.98291 14.0297 0.98291C13.9318 0.98291 13.8339 0.995497 13.7374 1.01787C12.3015 1.08749 10.9473 1.70645 9.95493 2.74667C8.9626 3.78689 8.40813 5.16878 8.40622 6.60641V7.42594L2.40233 1.42205L0.424805 3.39957L25.5984 28.5731L27.5759 26.5956ZM5.60916 14.9976H2.8121C2.8121 20.6924 7.0916 25.3971 12.6018 26.0893V28.9829H15.3989V26.0893C16.4812 25.9513 17.5373 25.6544 18.533 25.2083L16.3667 23.0433C15.5985 23.2712 14.8016 23.3875 14.0004 23.3888C9.37261 23.3888 5.60916 19.6253 5.60916 14.9976Z";
    const activeUnmutedPath2 = "M0.345276 0.111816C0.375256 1.83785 1.07427 3.48481 2.29494 4.70548C3.51562 5.92616 5.16257 6.62517 6.88861 6.65515L0.345276 0.111816Z";

    return (
        <TouchableOpacity
            onPress={handlePress}
            style={[
                styles.iconCircle,
                isMuted ? { backgroundColor: "rgba(119, 119, 119, 0.4)" } : { backgroundColor: "rgba(246, 246, 248, 1)" }
            ]}
        >
            <View style={styles.iconFrame}>
                <Svg width="28" height="29" viewBox="0 0 28 29" fill="none" >
                    {isMuted ? (
                        <>
                            <Path d={inactiveMutedPath1} fill="#F6F6F8"/>
                            <Path d={inactiveMutedPath2} fill="#F6F6F8"/>
                        </>
                    ) : (
                        <>
                            <Path d={activeUnmutedPath1} fill="#0C0D11"/>
                            <Path d={activeUnmutedPath2} fill="#0C0D11"/>
                        </>
                    )}
                </Svg>
            </View>
        </TouchableOpacity>
    );
}

function EndCallButton() {
    const handlePress = () => {
        console.log("End Call button pressed!");
    };

    return (
        <TouchableOpacity onPress={handlePress} style={styles.endCallButtonContainer}>
            <View style={styles.endCallButtonFrame}>
                <Svg style={styles.endCallSvg} width="37" height="17" viewBox="0 0 37 17" fill="none" >
                    <Path fillRule="evenodd" clipRule="evenodd" d="M11.0879 14.9959L12.4843 9.81239C13.2663 9.43257 15.6101 8.43609 18.6643 8.43609C21.5308 8.43609 23.7126 9.42028 24.441 9.79787L25.8396 14.9925L35.6447 16.5375L35.8234 15.8449C36.554 13.0409 36.5562 10.4469 35.8245 7.68426L35.7117 7.44184C33.2216 3.80336 26.9512 1.03846 20.1087 0.561447C12.6854 0.0442165 5.96813 2.28853 1.51749 6.73917C1.31641 6.94025 1.11867 7.14469 0.927643 7.35582L0.800292 7.49435L0.750022 7.67421C-0.0364368 10.467 -0.0364368 13.0677 0.751139 15.8594L0.941049 16.5297L11.0879 14.9959Z" fill="#F6F6F8"/>
                </Svg>
            </View>
        </TouchableOpacity>
    );
}

// --- Main CallScreen Component ---
export default function CallScreen() {
    const [seconds, setSeconds] = useState(0);
    const [showLanguageComponent, setShowLanguageComponent] = useState(false); // State to control Language component visibility
    const [currentLanguage, setCurrentLanguage] = useState('ENG'); // Default language
    const [isRecording, setIsRecording] = useState(false);
    const [loading, setLoading] = useState(false);
    const [callStatus, setCallStatus] = useState('idle'); // idle, initiating, connected, ended

    useEffect(() => {
        const timer = setInterval(() => {
            setSeconds(prevSeconds => prevSeconds + 1);
        }, 1000);
        return () => clearInterval(timer);
    }, []);

    useEffect(() => {
        const initializeSocket = async () => {
            const token = await AsyncStorage.getItem('accessToken');
            if (token) {
                connect(token);
                onVoiceTranscript((data) => {
                    console.log('Voice transcript:', data);
                    // Handle transcript (e.g., display or process)
                });
                onVoiceResponse((data) => {
                    console.log('Voice response:', data);
                    // Handle TTS playback
                });
                onCallInitiated(() => setCallStatus('initiating'));
                onCallAnswered(() => setCallStatus('connected'));
                onCallEnded(() => setCallStatus('ended'));
                onError((error) => {
                    console.error('Socket error:', error);
                    Alert.alert('Error', 'Connection error. Please try again.');
                });
            }
        };
        initializeSocket();
        return () => disconnect();
    }, []);

    const formatTime = (totalSeconds) => {
        const minutes = Math.floor(totalSeconds / 60);
        const remainingSeconds = totalSeconds % 60;
        const formattedMinutes = String(minutes).padStart(2, '0');
        const formattedSeconds = String(remainingSeconds).padStart(2, '0');
        return `${formattedMinutes}:${formattedSeconds}`;
    };

    const handleToggleLanguageDisplay = (isActive) => {
        setShowLanguageComponent(isActive);
    };

    const handleLanguageChange = (newLang) => {
        setCurrentLanguage(newLang);
    };

    const handleMicPress = async () => {
        setIsRecording(!isRecording);
        if (!isRecording) {
            // Start recording and processing via socket
            setLoading(true);
            try {
                // Mock audio data - in real app, get base64 from recording
                const mockAudioBase64 = 'mock_audio_base64_data';
                sendVoiceData(mockAudioBase64, currentLanguage);
                // Socket will handle STT, translation, TTS
            } catch (error) {
                console.error('Error sending voice data:', error);
                Alert.alert('Error', 'Failed to send audio. Please try again.');
            } finally {
                setLoading(false);
            }
        }
    };

    return (
        <ImageBackground source={require('./assets/snacks.png')} style={styles.blurContainer} blurRadius={10}>
            <View style={styles.darkOverlay}>

                {/* Conditionally render Language component at the very top */}
                {showLanguageComponent && (
                    <View style={styles.languageComponentWrapper}>
                        <Language currentLanguage={currentLanguage} onLanguageChange={handleLanguageChange} />
                    </View>
                )}

                {/* Caller Info and Timer */}
                <View style={styles.callerInfoContainer}>
                    <Text style={styles.callerName}>
                        {`Jhon Lexman`}
                    </Text>
                    <Text style={styles.callTimer}>
                        {formatTime(seconds)}
                    </Text>
                </View>

                {/* Spacer to push content down from the top */}
                <View style={styles.spacer} />

                {/* Top Row of Icons: Language, Dialpad, Speaker */}
                <View style={styles.iconsRow}>
                    <View style={styles.iconWrapper}>
                        <LanguageIcon onToggleLanguageDisplay={handleToggleLanguageDisplay} />
                        <Text style={styles.iconText}>Translate</Text>
                    </View>
                    <View style={styles.iconGap} />
                    <View style={styles.iconWrapper}>
                        <DialpadIcon />
                        <Text style={styles.iconText}>Dialpad</Text>
                    </View>
                    <View style={styles.iconGap} />
                    <View style={styles.iconWrapper}>
                        <TouchableOpacity onPress={handleMicPress} disabled={loading}>
                            <SpeakerIcon />
                        </TouchableOpacity>
                        <Text style={styles.iconText}>Speaker</Text>
                        {loading && <Text style={styles.loadingText}>Processing...</Text>}
                        {callStatus === 'initiating' && <Text style={styles.loadingText}>Initiating call...</Text>}
                        {callStatus === 'connected' && <Text style={styles.loadingText}>Connected</Text>}
                        {callStatus === 'ended' && <Text style={styles.loadingText}>Call ended</Text>}
                    </View>
                </View>

                <View style={{ height: 20 }} /> {/* Gap between icon rows */}

                {/* Bottom Row of Icons: Add Call, Video, Mute */}
                <View style={styles.iconsRow}>
                    <View style={styles.iconWrapper}>
                        <AddCallIcon />
                        <Text style={styles.iconText}>Add call</Text>
                    </View>
                    <View style={styles.iconGap} />
                    <View style={styles.iconWrapper}>
                        <VideoIcon />
                        <Text style={styles.iconText}>Video</Text>
                    </View>
                    <View style={styles.iconGap} />
                    <View style={styles.iconWrapper}>
                        <MuteIcon />
                        <Text style={styles.iconText}>Mute</Text>
                    </View>
                </View>

                <View style={{ height: 40 }} /> {/* 110px gap before End Call button */}

                {/* End Call Button */}
                <EndCallButton />

                <View style={{ height: 50 }} /> {/* Bottom padding */}

            </View>
        </ImageBackground>
    );
}

const styles = StyleSheet.create({
    blurContainer: {
        flex: 1,
    },
    darkOverlay: {
        flex: 1,
        backgroundColor: "rgba(12, 13, 17, 0.85)",
        justifyContent: 'space-between',
        alignItems: 'center',
        paddingVertical: 50,
    },
    // --- Icon Styling ---
    iconCircle: {
        height: 74,
        width: 74,
        backgroundColor: "rgba(119, 119, 119, 0.4)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        borderRadius: 45.5,
    },
    iconFrame: {
        height: '100%',
        width: '100%',
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
    },
    languageIconSvg: {
        overflow: "visible",
    },
    iconWrapper: {
        alignItems: 'center',
    },
    iconText: {
     
        textAlign: "center",
        color: "rgba(209, 209, 209, 1)",
        fontFamily: "Poppins",
        fontSize: 14,
        fontWeight: '400',
        lineHeight: 19.6,
        marginTop: 8,
    },
    iconGap: {
        width: 31,
    },
    // --- Layout for Icon Rows ---
    iconsRow: {
        flexDirection: 'row',
        justifyContent: 'center',
        alignItems: 'flex-start',
        width: '100%',
    },
    // --- Caller Info and Timer Styling ---
    callerInfoContainer: {
        width: '100%',
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        // Adjusted marginTop to give space above 'Jhon Lexman' when Language is hidden,
        // and allow Language to appear above it when active.
        marginTop: 20, // Reduced to allow space for Language component
    },
    callerName: {
        alignSelf: "stretch",
        textAlign: "center",
        color: "rgba(255, 255, 255, 1)",
        fontFamily: "Cabinet Grotesk",
        fontSize: 40,
        fontWeight: '500',
        lineHeight: 56,
    },
    callTimer: {
        textAlign: "center",
        color: "#D1D1D1",
        fontFamily: "Poppins",
        fontSize: 24,
        fontWeight: '400',
        lineHeight: 32,
    },
    spacer: {
        flex: 0.8, // Pushes content towards the bottom, maintaining space
    },
    // --- End Call Button Styling ---
    endCallButtonContainer: {
        height: 78,
        width: 78,
        backgroundColor: "rgba(216, 77, 70, 1)", // Red background
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        borderRadius: 48,
    },
    endCallButtonFrame: {
        height: 44,
        width: 44,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
    },
    endCallSvg: {
        overflow: "visible"
    },
    // --- Styles for the new Language component placement ---
    languageComponentWrapper: {
        // Position absolutely or use margin/padding to place it at the very top.
        // Using margin-top to push it from the very top of the darkOverlay.
        marginTop: 30, // Adjust as needed to align it at the top visually
        marginBottom: 20, // Add some space below it
        zIndex: 10, // Ensure it's above other elements if needed
    },
    // Styles from the `Language` component you provided
    languageContainer: {
       
        backgroundColor: "rgba(79, 79, 79, 0.4)",
        display: "flex",
        flexDirection: "row",
        alignItems: "center",
        justifyContent: "center",
        columnGap: 10,
        paddingHorizontal: 16,
        paddingVertical: 6,
        borderRadius: 48,
        flexWrap: "nowrap"
    },
    eNG: {
        textAlign: "center",
        color: "rgba(209, 209, 209, 1)",
        fontFamily: "Poppins",
        fontSize: 18,
        fontWeight: "400",
        lineHeight: 25.2
    },
    tablericontransfer: {
        height: 20,
        width: 20,
        display: "flex",
        alignItems: "center",
        justifyContent: "center"
    },
    vector: {
        overflow: "visible"
    },
    sPA: {
        textAlign: "center",
        color: "rgba(209, 209, 209, 1)",
        fontFamily: "Poppins",
        fontSize: 18,
        fontWeight: "400",
        lineHeight: 25.2
    },
    activeLanguage: {
        color: "#FF8A3D", // Highlight active language
    },
    loadingText: {
        fontSize: 12,
        color: "#D1D1D1",
        marginTop: 4,
        textAlign: "center",
    },
});
