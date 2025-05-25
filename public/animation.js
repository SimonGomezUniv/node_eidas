document.addEventListener('DOMContentLoaded', () => {
    // Actor and animation elements
    const rpEl = document.getElementById('rp');
    const walletEl = document.getElementById('wallet');
    const userEl = document.getElementById('user');

    const rpIcon = document.getElementById('rp-icon');
    const walletIcon = document.getElementById('wallet-icon');
    const userIcon = document.getElementById('user-icon');
    const userCheckmark = document.getElementById('user-checkmark'); // Added

    const animationArea = document.getElementById('animation-area');
    const qrCodeAnimEl = document.getElementById('qr-code-anim');
    const vpRequestAnimEl = document.getElementById('vp-request-anim');
    const sdJwtAnimEl = document.getElementById('sd-jwt-anim');

    // Text display and buttons
    const explanationTextEl = document.getElementById('explanation-text');
    const startBtn = document.getElementById('start-animation-btn');
    const nextStepBtn = document.getElementById('next-step-btn');
    const resetBtn = document.getElementById('reset-animation-btn');
    // userCheckmark is already defined above with other element constants

    const autoPlayCheckbox = document.getElementById('autoPlayCheckbox');
    const autoPlaySpeedLabel = document.getElementById('autoPlaySpeedLabel');
    const autoPlaySpeedInput = document.getElementById('autoPlaySpeed');
    const viewClaimsAnimEl = document.getElementById('view-claims-anim'); 
    if (viewClaimsAnimEl) setElementVisibility(viewClaimsAnimEl, false); // Initial hide
    const consentGrantedAnimEl = document.getElementById('consent-granted-anim'); // Added
    if (consentGrantedAnimEl) setElementVisibility(consentGrantedAnimEl, false); // Initial hide

    // DOM Element Null Checks
    if (!rpEl || !walletEl || !userEl || !rpIcon || !walletIcon || !userIcon || 
        !qrCodeAnimEl || !vpRequestAnimEl || !sdJwtAnimEl || !viewClaimsAnimEl || !consentGrantedAnimEl ||
        !explanationTextEl || !startBtn || !nextStepBtn || !resetBtn || 
        !autoPlayCheckbox || !autoPlaySpeedLabel || !autoPlaySpeedInput || !userCheckmark) {
        console.error("CRITICAL DOM SETUP ERROR: One or more essential DOM elements not found. Animation cannot proceed.");
        if(explanationTextEl) explanationTextEl.textContent = "Error: Animation components missing. Please reload.";
        return; 
    }
    // console.log("[DOMContentLoaded debug] All essential DOM elements appear to be found."); // Removed

    let isAutoPlay = false;
    let autoPlayTimeoutId = null;
    const DEFAULT_AUTOPLAY_DELAY = 2000; // ms

    let currentStep = 0;
    const steps = [
        {
            action: () => {
                // console.log("[steps[0].action debug] Entered."); // Removed
                if (explanationTextEl) {
                    explanationTextEl.textContent = "The Relying Party needs to verify the user's credentials.";
                } else {
                    console.error("[steps[0].action CRITICAL ERROR] explanationTextEl is null!");
                }
            },
            explanation: "The Relying Party (e.g., a website) needs to verify some information about the user."
        },
        {
            action: () => {
                qrCodeAnimEl.innerHTML = '▦'; // Ensure correct content
                
                // Position qrCodeAnimEl statically at RP's right edge
                const rpQrPos = getPosition(qrCodeAnimEl, rpEl, 'rightEdge', { x: 15, y: 0 }); // y:0 assumes connector-level vertical alignment
                qrCodeAnimEl.style.top = rpQrPos.top + 'px';
                qrCodeAnimEl.style.left = rpQrPos.left + 'px';
                qrCodeAnimEl.style.transform = 'translateX(0px)'; // Ensure no prior transform interferes, and no scale

                setElementVisibility(qrCodeAnimEl, true); // Make it visible at the static position
                
                rpIcon.style.transform = 'scale(1.1)'; // RP icon still active
            },
            explanation: "The Relying Party generates and displays a QR code."
        },
        {
            // Step 3: QR Moves to Wallet, User Scans
            action: () => {
                // Ensure QR code is visible if it was set up in Step 2
                // (setElementVisibility(qrCodeAnimEl, true) should have been called in Step 2)
                // No need to set innerHTML for qrCodeAnimEl here if Step 2 already did.

                // Animate QR code moving from RP to Wallet
                moveElement(qrCodeAnimEl, rpEl, walletEl, { 
                    startSide: 'rightEdge', // It starts from where Step 2 placed it (right of RP)
                    arrivalSide: 'leftEdge', 
                    xEdgeOffset: 15 
                });

                // User scanning animation occurs after QR code movement.
                // Duration of moveElement is 800ms by default. Add a small buffer.
                setTimeout(() => {
                    userIcon.style.transform = 'rotate(-10deg) scale(1.15)'; 
                    walletIcon.style.transform = 'scale(1.2)'; 
                    // Optionally, add a visual cue that QR is "at" the wallet,
                    // e.g., qrCodeAnimEl.style.borderColor = 'green'; (though it will be hidden soon)
                    explanationTextEl.innerHTML = `<b>Step ${currentStep + 1}:</b> User scans the QR code now displayed by their Wallet.`; // Update text during scan
                }, 800 + 50); // Delay matches moveElement duration + buffer

                // The QR code can be hidden later, perhaps at the start of Step 4.
                // Or, if scanning implies it's "processed", hide it after scan animation.
                setTimeout(() => {
                    setElementVisibility(qrCodeAnimEl, false);
                }, 800 + 50 + 1000); // Hide after scan visual has had time to be seen
            },
            explanation: "The QR code moves to the Wallet, and the User scans it."
        },
        {
            action: () => {
                // Wallet Fetches Presentation Request
                setElementVisibility(qrCodeAnimEl, false); // Hide QR
                rpIcon.style.transform = 'scale(1)';
                userIcon.style.transform = 'rotate(0deg) scale(1)';
                walletIcon.style.transform = 'scale(1.1)'; // Keep wallet slightly active

                // Simulate wallet fetching request from RP
                setElementVisibility(qrCodeAnimEl, false);
                rpIcon.style.transform = 'scale(1)';
                userIcon.style.transform = 'rotate(0deg) scale(1)';
                walletIcon.style.transform = 'scale(1.1)';
                vpRequestAnimEl.innerHTML = '📄 VP Request';
                moveElement(vpRequestAnimEl, walletEl, rpEl, { 
                    startSide: 'leftEdge', 
                    arrivalSide: 'rightEdge', 
                    xEdgeOffset: 10,
                    andBack: true, 
                    backDelay: 1000 
                });
            },
            explanation: "The Wallet retrieves the Presentation Request details from the Relying Party using the information from the QR code."
        },
        {
            // Step 5: Wallet Displays Claims, User Consents, Consent to Wallet
            action: () => {
                walletIcon.style.transform = 'scale(1.15)';
                setElementVisibility(vpRequestAnimEl, false); 

                // 1. "View Claims" animates from Wallet to User
                viewClaimsAnimEl.innerHTML = '📄 View Claims';
                moveElement(viewClaimsAnimEl, walletEl, userEl, {
                    startSide: 'rightEdge', 
                    arrivalSide: 'leftEdge',
                    xEdgeOffset: 10,
                    yOffset: -5 
                });

                // 2. User "consent" animation (nod and checkmark) occurs after "View Claims" arrives.
                setTimeout(() => {
                    userIcon.style.transform = 'translateY(-5px) scale(1.1)'; 
                    if (userCheckmark) {
                        const userIconRect = userIcon.getBoundingClientRect();
                        const userActorRect = userEl.getBoundingClientRect();
                        userCheckmark.style.top = (userIconRect.top - userActorRect.top + userIconRect.height / 2 - userCheckmark.offsetHeight /2 ) + 'px';
                        userCheckmark.style.left = (userIconRect.left - userActorRect.left + userIconRect.width + 5) + 'px';
                        userCheckmark.style.opacity = '1';
                        setTimeout(() => { userCheckmark.style.opacity = '0'; }, 1500);
                    }
                    setElementVisibility(viewClaimsAnimEl, false); // Hide "View Claims" after consent displayed

                    // 3. NEW: "Consent Granted" animates from User to Wallet
                    setTimeout(() => { // Delay this new animation slightly after checkmark appears
                        if (consentGrantedAnimEl) {
                            consentGrantedAnimEl.innerHTML = '✔ Consent Granted';
                            moveElement(consentGrantedAnimEl, userEl, walletEl, {
                                startSide: 'leftEdge', // User to Wallet (leftwards from User's perspective)
                                arrivalSide: 'rightEdge', // Arrives at Wallet's right edge
                                xEdgeOffset: 10,
                                yOffset: 5 // Slightly below connector line to differentiate
                            });
                            // Hide "Consent Granted" after it arrives at the wallet
                            setTimeout(() => {
                                setElementVisibility(consentGrantedAnimEl, false);
                            }, 800 + 50); // Matches moveElement duration + buffer
                        }
                    }, 500); // Delay after checkmark appears

                }, 800 + 50); // Delay for "View Claims" to arrive

                explanationTextEl.innerHTML = `<b>Step ${currentStep + 1}:</b> Wallet displays claims. User reviews, consents, and confirmed consent is sent to Wallet.`;
            },
            explanation: "Wallet displays claims to the User. User provides consent, which is then confirmed back to the Wallet."
        },
        {
            action: () => {
                // Wallet Sends SD-JWT
                userIcon.style.transform = 'rotate(0deg) scale(1)'; // Reset user icon
                walletIcon.style.transform = 'scale(1.1)'; // Keep wallet active

                userIcon.style.transform = 'rotate(0deg) scale(1)';
                walletIcon.style.transform = 'scale(1.1)';
                sdJwtAnimEl.innerHTML = '💳 SD-JWT';
                moveElement(sdJwtAnimEl, walletEl, rpEl, { 
                    startSide: 'leftEdge', 
                    arrivalSide: 'rightEdge', 
                    xEdgeOffset: 10 
                });
            },
            explanation: "The Wallet constructs and sends the Verifiable Presentation (containing SD-JWT with the selected claims) to the Relying Party."
        },
        {
            action: () => {
                // RP Verifies and Completes
                rpIcon.style.transform = 'scale(1.1)';
                walletIcon.style.transform = 'scale(1)'; // Reset wallet
                // SD-JWT "arrives"
                explanationTextEl.textContent = "RP verifies the SD-JWT. Access granted or transaction completed.";
                // Optionally, show a success message on RP
                setTimeout(() => {
                    rpIcon.style.transform = 'scale(1)';
                    setElementVisibility(sdJwtAnimEl, false); // Hide SD-JWT after a delay
                    explanationTextEl.innerHTML = "<strong>Flow Complete!</strong> The Relying Party has verified the necessary information using OpenID4VP.";
                    nextStepBtn.style.display = 'none';
                    resetBtn.textContent = "Restart Animation";
                }, 2000);
            },
            explanation: "The Relying Party verifies the signature and the claims in the SD-JWT. If valid, the transaction is completed (e.g., user is logged in, age is verified)."
        }
        // More steps can be added here
    ];

    function setElementVisibility(el, visible) {
        if (visible) {
            el.style.opacity = '1';
            el.style.display = 'flex'; // Or 'block' if that's more appropriate for the element
        } else {
            el.style.opacity = '0';
            // Delay hiding so opacity transition is visible
            setTimeout(() => { if (el.style.opacity === '0') el.style.display = 'none'; }, 500);
        }
    }

    // Helper function to calculate position relative to animationArea
    function getPosition(targetEl, relativeToEl, position = 'center', offset = { x: 0, y: 0 }) {
        const parentEl = document.querySelector('.actors-and-connectors');
        if (!parentEl) return { top: 0, left: 0 }; // Should not happen
        const parentRect = parentEl.getBoundingClientRect();

        const relativeRect = relativeToEl.getBoundingClientRect();
        // Ensure targetEl is visible to get correct dimensions, then restore display if needed
        const originalDisplay = targetEl.style.display;
        if (originalDisplay === 'none') targetEl.style.display = 'flex'; // Or 'block' if more appropriate
        const targetRect = targetEl.getBoundingClientRect();
        if (originalDisplay === 'none') targetEl.style.display = originalDisplay; // Restore


        let top = 0;
        let left = 0;

        const primaryConnector = document.getElementById('connector-rp-wallet');
        if (primaryConnector) {
            const connectorRect = primaryConnector.getBoundingClientRect();
            top = (connectorRect.top + connectorRect.height / 2) - parentRect.top - (targetRect.height / 2);
        } else {
            top = (parentRect.height / 2) - (targetRect.height / 2);
        }
        top += (offset.y || 0);

        if (position === 'leftEdge') {
            left = relativeRect.left - parentRect.left - targetRect.width - (offset.x || 0);
        } else if (position === 'rightEdge') {
            left = relativeRect.right - parentRect.left + (offset.x || 0);
        } else { // 'center'
            left = (relativeRect.left + relativeRect.width / 2) - parentRect.left - (targetRect.width / 2) + (offset.x || 0);
        }
        return { top, left };
    }
    
    // Function to set initial style for moving element (REMOVED as moveElement now handles initial setup)
    // function styleForMoving(element, startElement, startPosition = 'center', startOffset = {x:0, y:0}) { ... }


    function moveElement(element, fromEl, toEl, options = {}) {
        const { 
            yOffset = 0, 
            duration = 800, 
            andBack = false, 
            backDelay = 500, 
            startSide = 'rightEdge',
            arrivalSide = 'leftEdge',
            xEdgeOffset = 10 
        } = options;

        const initialPos = getPosition(element, fromEl, startSide, { x: xEdgeOffset, y: yOffset });
        element.style.top = initialPos.top + 'px';
        element.style.left = initialPos.left + 'px';
        element.style.transform = 'translateX(0px)'; // Removed scale
        setElementVisibility(element, true); // Element becomes visible at its starting position

        const targetPos = getPosition(element, toEl, arrivalSide, { x: xEdgeOffset, y: yOffset });
        const deltaX = targetPos.left - initialPos.left;

        setTimeout(() => {
            element.style.transform = `translateX(${deltaX}px)`; // Removed scale
        }, 50);

        if (andBack) {
            setTimeout(() => {
                element.style.transform = `translateX(0px)`; // Removed scale
                setTimeout(() => {
                    setElementVisibility(element, false);
                }, duration);
            }, duration + backDelay);
        }
    }

    function handleNextStep() {
        if (isAutoPlay && autoPlayTimeoutId) { // If called by timeout, clear it
            clearTimeout(autoPlayTimeoutId);
            autoPlayTimeoutId = null;
        }

        if (currentStep < steps.length - 1) {
            executeStep(currentStep + 1);
        } else { // Reached end of animation
            if (isAutoPlay) autoPlayCheckbox.checked = false; // Turn off autoplay if it reached the end
            isAutoPlay = false;
            autoPlaySpeedLabel.style.display = 'none';
            nextStepBtn.style.display = 'none';
            if (autoPlayTimeoutId) clearTimeout(autoPlayTimeoutId); // Ensure no dangling timeout
        }
    }

    function executeStep(stepIndex) {
        if (!steps || typeof stepIndex !== 'number' || stepIndex < 0 || stepIndex >= steps.length) {
            console.error(`[executeStep ABORT] Invalid stepIndex: ${stepIndex} or steps array issue.`);
            return;
        }
        currentStep = stepIndex;
        const step = steps[currentStep];
        if (!step || typeof step.action !== 'function' || typeof step.explanation !== 'string') {
            console.error(`[executeStep ABORT] Invalid step object at index: ${currentStep}. Step:`, step);
            return;
        }

        // console.log(`[executeStep ENTRY debug] Index: ${stepIndex}, currentStep updated to: ${currentStep}, isAutoPlay: ${isAutoPlay}`); // Removed

        rpIcon.style.transform = 'scale(1)';
        walletIcon.style.transform = 'scale(1)';
        userIcon.style.transform = 'scale(1)';

        // console.log(`[executeStep debug] About to call action for step: ${currentStep}`); // Removed
        try {
            step.action();
            // console.log(`[executeStep debug] Action for step ${currentStep} completed.`); // Removed
        } catch (e) {
            console.error(`[executeStep CRITICAL ERROR] Error in step ${currentStep} action:`, e);
            return; 
        }

        if (explanationTextEl) {
            explanationTextEl.innerHTML = `<b>Step ${currentStep + 1}:</b> ${step.explanation}`;
        } else {
            console.error("[executeStep CRITICAL ERROR] explanationTextEl is null!");
        }

        if (resetBtn) {
            resetBtn.style.display = 'inline-block';
        } else {
            console.error("[executeStep CRITICAL ERROR] resetBtn is null!");
        }
        
        if (!nextStepBtn) {
            console.error("[executeStep CRITICAL ERROR] nextStepBtn is null! Cannot update button state.");
            return; 
        }

        if (currentStep < steps.length - 1) { 
            // console.log(`[executeStep debug] Not last step. Setting nextStepBtn visible. isAutoPlay: ${isAutoPlay}. Current btn display: ${nextStepBtn.style.display}`); // Removed
            nextStepBtn.style.display = 'inline-block'; 

            if (isAutoPlay) {
                nextStepBtn.textContent = 'Pause';
                const delay = (parseInt(autoPlaySpeedInput.value, 10) || 2) * 1000;
                // console.log(`[executeStep debug] Autoplay ON. Setting timeout. Delay: ${delay}ms. Current autoPlayTimeoutId: ${autoPlayTimeoutId}`); // Removed
                if (autoPlayTimeoutId) clearTimeout(autoPlayTimeoutId);
                autoPlayTimeoutId = setTimeout(handleNextStep, delay);
                // console.log(`[executeStep debug] autoPlayTimeoutId set to: ${autoPlayTimeoutId}`); // Removed
            } else { 
                nextStepBtn.textContent = 'Next Step';
                // console.log(`[executeStep debug] Manual mode. Button text: 'Next Step'. Clearing autoPlayTimeoutId: ${autoPlayTimeoutId}`); // Removed
                if (autoPlayTimeoutId) {
                    clearTimeout(autoPlayTimeoutId);
                    autoPlayTimeoutId = null;
                }
            }
        } else { 
            // console.log(`[executeStep debug] This IS the last step. Hiding nextStepBtn. Current btn display: ${nextStepBtn.style.display}`); // Removed
            nextStepBtn.style.display = 'none';
            if (isAutoPlay) {
                // console.log(`[executeStep debug] Autoplay was ON, reached end. Clearing timeout: ${autoPlayTimeoutId}`); // Removed
                if (autoPlayTimeoutId) clearTimeout(autoPlayTimeoutId);
                isAutoPlay = false;
                if (autoPlayCheckbox) autoPlayCheckbox.checked = false; else console.error("autoPlayCheckbox is null");
                if (autoPlaySpeedLabel) autoPlaySpeedLabel.style.display = 'none'; else console.error("autoPlaySpeedLabel is null");
            }
        }
    }

    autoPlayCheckbox.addEventListener('change', (event) => {
        isAutoPlay = event.target.checked;
        // console.log(`[autoPlayCheckbox debug] Changed. isAutoPlay is now: ${isAutoPlay}. currentStep: ${currentStep}, startBtn visible: ${startBtn.style.display !== 'none'}`); // Removed

        if (autoPlayTimeoutId) {
            // console.log(`[autoPlayCheckbox debug] Clearing autoPlayTimeoutId: ${autoPlayTimeoutId} due to mode change.`); // Removed
            clearTimeout(autoPlayTimeoutId);
            autoPlayTimeoutId = null;
        }

        if (isAutoPlay) {
            if (autoPlaySpeedLabel) autoPlaySpeedLabel.style.display = 'inline'; else console.error("autoPlaySpeedLabel is null");
        } else {
            if (autoPlaySpeedLabel) autoPlaySpeedLabel.style.display = 'none'; else console.error("autoPlaySpeedLabel is null");
        }

        if (startBtn.style.display === 'none') { 
            // console.log(`[autoPlayCheckbox debug] Animation in progress. Calling executeStep(${currentStep}) to update UI.`); // Removed
            executeStep(currentStep);
        } else {
            if (!nextStepBtn) {
                console.error("[autoPlayCheckbox CRITICAL ERROR] nextStepBtn is null!");
                return;
            }
            if (isAutoPlay) {
                nextStepBtn.textContent = 'Pause';
            } else {
                nextStepBtn.textContent = 'Next Step';
            }
            // console.log(`[autoPlayCheckbox debug] Animation not started. Pre-set nextStepBtn text to: ${nextStepBtn.textContent}. Ensuring it's hidden.`); // Removed
            nextStepBtn.style.display = 'none'; 
        }
    });

    startBtn.addEventListener('click', () => {
        // console.log("[startBtn] Clicked. Initial isAutoPlay: " + isAutoPlay + ", currentStep: " + currentStep); // Removed
        startBtn.style.display = 'none';
        resetBtn.style.display = 'inline-block';
        
        // console.log("[startBtn] Attempting to hide qrCodeAnimEl"); // Removed
        setElementVisibility(qrCodeAnimEl, false); 
        // console.log("[startBtn] Attempting to hide vpRequestAnimEl"); // Removed
        setElementVisibility(vpRequestAnimEl, false);
        // console.log("[startBtn] Attempting to hide sdJwtAnimEl"); // Removed
        setElementVisibility(sdJwtAnimEl, false);
        // console.log("[startBtn] Attempting to hide viewClaimsAnimEl"); // Removed
        setElementVisibility(viewClaimsAnimEl, false);

        // console.log("[startBtn] Calling executeStep(0)"); // Removed
        executeStep(0); 
    });

    nextStepBtn.addEventListener('click', () => {
        // console.log(`[nextStepBtn] Clicked. isAutoPlay: ${isAutoPlay}, current autoPlayTimeoutId: ${autoPlayTimeoutId}, currentStep: ${currentStep}`); // Removed
        if (isAutoPlay) { 
            if (autoPlayTimeoutId) { 
                // console.log(`[nextStepBtn] PAUSING. Clearing autoPlayTimeoutId: ${autoPlayTimeoutId}`); // Removed
                clearTimeout(autoPlayTimeoutId);
                autoPlayTimeoutId = null;
                nextStepBtn.textContent = 'Resume';
            } else { 
                if (startBtn.style.display === 'none' && currentStep < steps.length - 1) {
                     // console.log(`[nextStepBtn] RESUMING. Setting text to 'Pause' and calling handleNextStep.`); // Removed
                     nextStepBtn.textContent = 'Pause'; 
                     handleNextStep(); 
                } else {
                    // console.log(`[nextStepBtn] Resume clicked but not in a resumable state (e.g. animation ended or not started).`); // Removed
                }
            }
        } else { 
            // console.log(`[nextStepBtn] Manual step. Calling handleNextStep().`); // Removed
            handleNextStep(); 
        }
    });

    function handleNextStep() {
        // console.log(`[handleNextStep] Called. currentStep before increment: ${currentStep}. Current autoPlayTimeoutId: ${autoPlayTimeoutId}`); // Removed
        if (isAutoPlay && autoPlayTimeoutId) { 
            // console.log(`[handleNextStep] Cleared autoPlayTimeoutId: ${autoPlayTimeoutId}`); // Removed
            clearTimeout(autoPlayTimeoutId);
            autoPlayTimeoutId = null;
        }

        if (currentStep < steps.length - 1) {
            // console.log(`[handleNextStep] About to call executeStep(${currentStep + 1})`); // Removed
            executeStep(currentStep + 1);
        } else { 
            if (isAutoPlay) autoPlayCheckbox.checked = false; 
            isAutoPlay = false;
            autoPlaySpeedLabel.style.display = 'none';
            nextStepBtn.style.display = 'none';
            if (autoPlayTimeoutId) {
                // console.log(`[handleNextStep] End of anim in autoplay: Clearing autoPlayTimeoutId: ${autoPlayTimeoutId}`); // Removed
                clearTimeout(autoPlayTimeoutId);
                autoPlayTimeoutId = null;
            }
        }
    }

    resetBtn.addEventListener('click', () => {
        // console.log("[resetBtn] Clicked or called. Initial currentStep: " + currentStep + ", isAutoPlay: " + isAutoPlay); // Removed
        currentStep = 0;
        setElementVisibility(qrCodeAnimEl, false);
        setElementVisibility(vpRequestAnimEl, false);
        setElementVisibility(sdJwtAnimEl, false);
        if (viewClaimsAnimEl) setElementVisibility(viewClaimsAnimEl, false);
        if (consentGrantedAnimEl) setElementVisibility(consentGrantedAnimEl, false); // Added

        rpIcon.style.transform = 'scale(1)';
        walletIcon.style.transform = 'scale(1)';
        userIcon.style.transform = 'translateY(0px) scale(1) rotate(0deg)';
        if (userCheckmark) userCheckmark.style.opacity = '0';
        
        if (autoPlayTimeoutId) {
            // console.log(`[resetBtn] Clearing autoPlayTimeoutId: ${autoPlayTimeoutId}`); // Removed
            clearTimeout(autoPlayTimeoutId);
            autoPlayTimeoutId = null;
        }
        isAutoPlay = false;
        autoPlayCheckbox.checked = false;
        // autoPlayCheckbox.disabled = false; // Re-enable if it was disabled
        autoPlaySpeedLabel.style.display = 'none';
        
        explanationTextEl.textContent = "Welcome! Click 'Start' to see the animation.";
        startBtn.style.display = 'inline-block';
        // console.log("[resetBtn] Setting nextStepBtn.style.display = 'none'"); // Removed
        nextStepBtn.style.display = 'none'; 
        nextStepBtn.textContent = 'Next Step'; 
        resetBtn.style.display = 'none';
    });

    // Initial call to set up the page before animation starts
    // console.log("[DOMContentLoaded] About to click resetBtn programmatically"); // Removed
    if (resetBtn) resetBtn.click(); 
    // console.log("[DOMContentLoaded] resetBtn programmatically clicked. Initial currentStep: " + currentStep + ", Initial isAutoPlay: " + isAutoPlay); // Removed
    // console.log("[DOMContentLoaded] End"); // Removed
});
